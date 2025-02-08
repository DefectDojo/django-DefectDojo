import hashlib
import json
import textwrap
from datetime import date

from dojo.models import Finding


class AWSProwlerV3Parser:
    def process_json(self, file, test):
        dupes = {}

        data = json.load(file)
        for deserialized in data:

            status = deserialized.get("Status")
            if status.upper() != "FAIL":
                continue

            account = deserialized.get("AccountId")
            region = deserialized.get("Region")
            provider = deserialized.get("Provider")
            compliance = str(deserialized.get("Compliance"))
            result_extended = deserialized.get("StatusExtended")
            general_description = deserialized.get("Description")
            asff_compliance_type = " / ".join(deserialized.get("CheckType"))
            severity = deserialized.get("Severity", "Info").capitalize()
            aws_service_name = deserialized.get("ServiceName")
            impact = deserialized.get("Risk")
            mitigation = deserialized.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
            mitigation = str(mitigation) + "\n" + str(deserialized.get("Remediation", {}).get("Code"))
            documentation = deserialized.get("Remediation", {}).get("Recommendation", {}).get("Url")
            documentation = str(documentation) + "\n" + str(deserialized.get("RelatedUrl"))
            security_domain = deserialized.get("ResourceType")
            timestamp = deserialized.get("AssessmentStartTime")
            resource_arn = deserialized.get("ResourceArn")
            account_id = deserialized.get("AccountId")
            resource_id = deserialized.get("ResourceId")
            unique_id_from_tool = deserialized.get("FindingUniqueId")
            if not resource_arn or resource_arn == "":
                component_name = str(provider) + "-" + str(account_id) + "-" + str(region) + "-" + str(resource_id)
            else:
                component_name = resource_arn

            description = "**Issue:** " + str(result_extended) + \
                "\n**Description:** " + str(general_description) + \
                "\n**AWS Account:** " + str(account) + " | **Region:** " + str(region) + \
                "\n**Compliance:** " + str(compliance) + \
                "\n**AWS Service:** " + str(aws_service_name) + \
                "\n**ASFF Compliance Type:** " + str(asff_compliance_type) + \
                "\n**Security Domain:** " + str(security_domain)

            # improving key to get duplicates
            dupe_key = hashlib.sha256(unique_id_from_tool.encode("utf-8")).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description + "\n\n"
                find.nb_occurences += 1
            else:
                find = Finding(
                    title=textwrap.shorten(result_extended, 150),
                    cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                    test=test,
                    description=description,
                    component_name=component_name,
                    unique_id_from_tool=unique_id_from_tool,
                    severity=severity,
                    references=documentation,
                    date=date.fromisoformat(timestamp[:10]),
                    static_finding=True,
                    dynamic_finding=False,
                    nb_occurences=1,
                    mitigation=mitigation,
                    impact=impact,
                )
                dupes[dupe_key] = find

        return list(dupes.values())
