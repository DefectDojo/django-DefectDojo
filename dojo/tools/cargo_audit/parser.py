import hashlib
import json

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData
from dojo.utils import parse_cvss_data


class CargoAuditParser:

    """A class that can be used to parse the cargo audit JSON report file"""

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Cargo Audit Parser.

        Fields:
        - title: Set to the title from Cargo Audit Scanner
        - severity: Derived from the advisory CVSS vector when available, otherwise "High".
        - tags: Set to the tags from Cargo Audit Scanner if they are provided.
        - description: Set to the description from Cargo Audit Scanner and joined with URL provided.
        - component_name: Set to name of package provided by the Cargo Audit Scanner.
        - component_version: Set to version of package provided by the Cargo Audit Scanner.
        - cvssv3: Set to the CVSS v3.x vector from the advisory if one is provided.
        - cvssv3_score: Set to the CVSS v3.x score computed from the vector if one is provided.
        - cvssv4: Set to the CVSS v4.0 vector from the advisory if one is provided.
        - cvssv4_score: Set to the CVSS v4.0 score computed from the vector if one is provided.
        - vuln_id_from_tool: Set to id provided by the Cargo Audit Scanner.
        - publish_date: Set to date provided by the Cargo Audit Scanner.
        - nb_occurences: Set to 1 by the parser.
        - mitigation: Set to package_name and versions if information is available.

        NOTE: This parser supports tags
        """
        return [
            "title",
            "severity",
            "tags",
            "description",
            "component_name",
            "component_version",
            "cvssv3",
            "cvssv3_score",
            "cvssv4",
            "cvssv4_score",
            "vuln_id_from_tool",
            "publish_date",
            "nb_occurences",
            "mitigation",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Cargo Audit Parser.

        Fields:
        - severity: Set to "High" regardless of context.
        - component_name: Set to name of package provided by the Cargo Audit Scanner.
        - component_version: Set to version of package provided by the Cargo Audit Scanner.
        - vuln_id_from_tool: Set to id provided by the Cargo Audit Scanner.

        NOTE: vulnerability_ids is not provided by parser.
        NOTE: vulnerability_ids appears to be stored in unsaved_vulnerability_ids.
        """
        return [
            "severity",
            "component_name",
            "component_version",
            "vuln_id_from_tool",
        ]

    def get_scan_types(self):
        return ["CargoAudit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CargoAudit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import JSON output for cargo audit scan report."

    def get_findings(self, filename, test):
        data = json.load(filename)
        dupes = {}
        if data.get("vulnerabilities"):
            for item in data.get("vulnerabilities").get("list"):
                advisory = item.get("advisory")
                vuln_id = advisory.get("id")
                vulnerability_ids = [advisory.get("id")]
                categories = f"**Categories:** {', '.join(advisory['categories'])}" if "categories" in advisory else ""
                description = categories + f"\n**Description:** `{advisory.get('description')}`"

                if item["affected"] is not None and "functions" in item["affected"]:
                    affected_func = [
                        f"{func}: {', '.join(versions)}" for func, versions in item["affected"]["functions"].items()
                    ]
                    description += f"\n**Affected functions**: {', '.join(affected_func)}"

                references = f"{advisory.get('url')}\n" + "\n".join(
                    advisory["references"],
                )
                date = advisory.get("date")

                for alias in advisory.get("aliases", []):
                    vulnerability_ids.append(alias)

                package_name = item.get("package").get("name")
                package_version = item.get("package").get("version")
                title = f"[{package_name} {package_version}] {advisory.get('title')}"
                # The advisory may carry a CVSS vector (v3.x or v4.0). When present, use it
                # to populate the CVSS fields and derive severity; otherwise fall back to "High".
                cvss_data = {}
                cvss_vector = advisory.get("cvss")
                if cvss_vector:
                    try:
                        cvss_data = parse_cvss_data(cvss_vector)
                    except Exception:
                        cvss_data = {}
                severity = cvss_data.get("severity") or "High"
                tags = advisory.get("keywords") if "keywords" in advisory else []
                try:
                    mitigation = f"**Update {package_name} to** {', '.join(item['versions']['patched'])}"
                except KeyError:
                    mitigation = "No information about patched version"
                dupe_key = hashlib.sha256(
                    (vuln_id + date + package_name + package_version).encode(
                        "utf-8",
                    ),
                ).hexdigest()

                if dupe_key in dupes:
                    finding = dupes[dupe_key]
                    finding.nb_occurences += 1
                else:
                    finding = Finding(
                        title=title,
                        test=test,
                        severity=severity,
                        description=description,
                        component_name=package_name,
                        component_version=package_version,
                        cvssv3=cvss_data.get("cvssv3"),
                        cvssv3_score=cvss_data.get("cvssv3_score"),
                        cvssv4=cvss_data.get("cvssv4"),
                        cvssv4_score=cvss_data.get("cvssv4_score"),
                        vuln_id_from_tool=vuln_id,
                        publish_date=date,
                        nb_occurences=1,
                        references=references,
                        mitigation=mitigation,
                    )
                    finding.unsaved_tags = tags
                    finding.unsaved_vulnerability_ids = vulnerability_ids
                    if settings.V3_FEATURE_LOCATIONS and package_name:
                        finding.unsaved_locations.append(
                            LocationData.dependency(purl_type="cargo", name=package_name, version=package_version),
                        )
                    dupes[dupe_key] = finding
        return list(dupes.values())
