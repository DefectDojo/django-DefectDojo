
import hashlib
import json
import textwrap
from datetime import date

from dojo.models import Finding


class AWSProwlerV3Parser:
    SCAN_TYPE = ["AWS Prowler V3"]

    def get_scan_types(self):
        return AWSProwlerV3Parser.SCAN_TYPE

    def get_label_for_scan_types(self, scan_type):
        return AWSProwlerV3Parser.SCAN_TYPE[0]

    def get_description_for_scan_types(self, scan_type):
        return "Exports from AWS Prowler v3 in JSON format or from Prowler v4 in OCSF-JSON format."

    def get_findings(self, file, test):
        if file.name.lower().endswith('.ocsf.json'):
            return self.process_ocsf_json(file, test)
        elif file.name.lower().endswith('.json'):
            return self.process_json(file, test)
        else:
            msg = 'Unknown file format'
            raise ValueError(msg)


    def process_ocsf_json(self, file, test):
        dupes = {}

        data = json.load(file)
        # mapping of json fields between Prowler v3 and v4:
        # https://docs.prowler.com/projects/prowler-open-source/en/latest/tutorials/reporting/#json
        for deserialized in data:

            status = deserialized.get('status_code')
            if status.upper() != 'FAIL':
                continue

            account_id = deserialized.get('cloud', {}).get('account', {}).get("uid", '')
            region = deserialized.get('resources', [{}])[0].get('region', '')
            provider = deserialized.get('cloud', {}).get('provider', '')
            compliance = ''
            compliance_field = deserialized.get('unmapped', {}).get("compliance", {})
            if compliance_field:
                compliance = ' | '.join([f"{key}:{','.join(value)}" for key, value in compliance_field.items()])
            result_extended = deserialized.get('status_detail')
            general_description = deserialized.get('finding_info', {}).get('desc', '')
            asff_compliance_type = deserialized.get('unmapped', {}).get('check_type', '')
            severity = deserialized.get('severity', 'Info').capitalize()
            aws_service_name = deserialized.get('resources', [{}])[0].get('group', {}).get('name', '')
            impact = deserialized.get('risk_details')
            mitigation = deserialized.get('remediation', {}).get("desc", '')
            documentation = deserialized.get('remediation', {}).get("references", '')
            documentation = str(documentation) + "\n" + str(deserialized.get('unmapped', {}).get('related_url', ''))
            security_domain = deserialized.get('resources', [{}])[0].get('type', '')
            timestamp = deserialized.get("event_time")
            resource_arn = deserialized.get('resources', [{}])[0].get('uid', '')
            resource_id = deserialized.get('resources', [{}])[0].get('name', '')
            unique_id_from_tool = deserialized.get('finding_info', {}).get('uid', '')
            if not resource_arn or resource_arn == "":
                component_name = str(provider) + "-" + str(account_id) + "-" + str(region) + "-" + str(resource_id)
            else:
                component_name = resource_arn

            description = "**Issue:** " + str(result_extended) + \
                          "\n**Description:** " + str(general_description) + \
                          "\n**AWS Account:** " + str(account_id) + \
                          "\n**Region:** " + str(region) + \
                          "\n**AWS Service:** " + str(aws_service_name) + \
                          "\n**Security Domain:** " + str(security_domain) + \
                          "\n**Compliance:** " + str(compliance) + \
                          "\n**ASFF Compliance Type:** " + str(asff_compliance_type)

            # improving key to get duplicates
            dupe_key = hashlib.sha256(unique_id_from_tool.encode('utf-8')).hexdigest()
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

    def process_json(self, file, test):
        dupes = {}

        data = json.load(file)
        for deserialized in data:

            status = deserialized.get('Status')
            if status.upper() != 'FAIL':
                continue

            account = deserialized.get('AccountId')
            region = deserialized.get('Region')
            provider = deserialized.get('Provider')
            compliance = str(deserialized.get('Compliance'))
            result_extended = deserialized.get('StatusExtended')
            general_description = deserialized.get('Description')
            asff_compliance_type = " / ".join(deserialized.get('CheckType'))
            severity = deserialized.get('Severity', 'Info').capitalize()
            aws_service_name = deserialized.get('ServiceName')
            impact = deserialized.get('Risk')
            mitigation = deserialized.get('Remediation', {}).get('Recommendation', {}).get("Text", '')
            mitigation = str(mitigation) + "\n" + str(deserialized.get('Remediation', {}).get('Code'))
            documentation = deserialized.get('Remediation', {}).get('Recommendation', {}).get("Url")
            documentation = str(documentation) + "\n" + str(deserialized.get('RelatedUrl'))
            security_domain = deserialized.get('ResourceType')
            timestamp = deserialized.get('AssessmentStartTime')
            resource_arn = deserialized.get('ResourceArn')
            account_id = deserialized.get('AccountId')
            resource_id = deserialized.get('ResourceId')
            unique_id_from_tool = deserialized.get('FindingUniqueId')
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
            dupe_key = hashlib.sha256(unique_id_from_tool.encode('utf-8')).hexdigest()
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

    def formatview(self, depth):
        if depth > 1:
            return "* "
        else:
            return ""
