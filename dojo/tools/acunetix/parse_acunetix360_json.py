import json

import html2text
from cvss import parser as cvss_parser
from dateutil import parser

from dojo.models import Endpoint, Finding


class AcunetixJSONParser:

    """This parser is written for Acunetix JSON Findings."""

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Acunetix 360 Parser.

        Fields:
        - title: Set to the name outputted by the Acunetix 360 Scanner.
        - description: Set to Description variable outputted from Acunetix 360 Scanner.
        - severity: Set to severity from Acunetix 360 Scanner converted into Defect Dojo format.
        - mitigation: Set to RemedialProcedure variable outputted from Acunetix 360 Scanner if it is present.
        - impact: Set to Impact variable outputted from Acunetix 360 Scanner if it is present.
        - date: Set to FirstSeenDate variable outputted from Acunetix 360 Scanner if present. If not, it is set to Generated variable from output.
        - cwe: Set to converted cwe in Classification variable outputted from Acunetix 360 Scanner if it is present.
        - static_finding: Set to True.
        - cvssv3: Set to converted cvssv3 in Classification variable outputted from Acunetix 360 Scanner if it is present.
        - risk_accepted: Set to True if AcceptedRisk is present in State variable outputted from Acunetix 360 Scanner. No value if variable is not present.
        - active: Set to false.
        """
        return [
            "title",
            "description",
            "severity",
            "mitigation",
            "impact",
            "date",
            "cwe",
            "static_finding",
            "cvssv3",
            "risk_accepted",
            "active",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Acunetix 360 Parser.
        - title: Set to the name outputted by the Acunetix 360 Scanner.
        - description: Set to Description variable outputted from Acunetix 360 Scanner.

        Fields:
        """
        return [
            "title",
            "description",
        ]

    def get_findings(self, filename, test):
        dupes = {}
        data = json.load(filename)
        dupes = {}
        scan_date = parser.parse(data["Generated"], dayfirst=True)
        text_maker = html2text.HTML2Text()
        text_maker.body_width = 0
        for item in data["Vulnerabilities"]:
            title = item["Name"]
            findingdetail = text_maker.handle(item.get("Description", ""))
            if item["Classification"] is not None and "Cwe" in item["Classification"]:
                try:
                    cwe = int(item["Classification"]["Cwe"].split(",")[0])
                except BaseException:
                    cwe = None
            else:
                cwe = None
            sev = item["Severity"]
            if sev not in {"Info", "Low", "Medium", "High", "Critical"}:
                sev = "Info"
            if item["RemedialProcedure"] is not None:
                mitigation = text_maker.handle(item.get("RemedialProcedure", ""))
            else:
                mitigation = None
            if item["RemedyReferences"] is not None:
                references = text_maker.handle(item.get("RemedyReferences", ""))
            else:
                references = None
            if "LookupId" in item:
                lookupId = item["LookupId"]
                if references is None:
                    references = (
                        f"https://online.acunetix360.com/issues/detail/{lookupId}\n"
                    )
                else:
                    references = (
                        f"https://online.acunetix360.com/issues/detail/{lookupId}\n"
                        + references
                    )
            url = item["Url"]
            impact = text_maker.handle(item.get("Impact", "")) if item["Impact"] is not None else None
            dupe_key = title
            request = item["HttpRequest"]["Content"]
            if request is None or len(request) <= 0:
                request = "Request Not Found"
            response = item["HttpResponse"]["Content"]
            if response is None or len(response) <= 0:
                response = "Response Not Found"
            finding = Finding(
                title=title,
                test=test,
                description=findingdetail,
                severity=sev.title(),
                mitigation=mitigation,
                impact=impact,
                date=scan_date,
                references=references,
                cwe=cwe,
                static_finding=True,
            )
            if (
                (item["Classification"] is not None)
                and (item["Classification"]["Cvss"] is not None)
                and (item["Classification"]["Cvss"]["Vector"] is not None)
            ):
                cvss_objects = cvss_parser.parse_cvss_from_text(
                    item["Classification"]["Cvss"]["Vector"],
                )
                if len(cvss_objects) > 0:
                    finding.cvssv3 = cvss_objects[0].clean_vector()

            if item["State"] is not None:
                state = [x.strip() for x in item["State"].split(",")]
                if "AcceptedRisk" in state:
                    finding.risk_accepted = True
                    finding.active = False
                elif "FalsePositive" in state:
                    finding.false_p = True
                    finding.active = False
            finding.unsaved_req_resp = [{"req": request, "resp": response}]
            finding.unsaved_endpoints = [Endpoint.from_uri(url)]
            if item.get("FirstSeenDate"):
                parseddate = parser.parse(item["FirstSeenDate"], dayfirst=True)
                finding.date = parseddate
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.unsaved_req_resp.extend(finding.unsaved_req_resp)
                find.unsaved_endpoints.extend(finding.unsaved_endpoints)
            else:
                dupes[dupe_key] = finding
        return list(dupes.values())
