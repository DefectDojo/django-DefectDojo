from datetime import datetime
from dojo.models import Finding, Endpoint


class GuardDuty(object):
    def get_item(self, finding: dict, test):
        finding_id = finding.get("Id", "")
        title = finding.get("Title", "")
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
        mitigation = ""
        impact = []
        references = []
        unsaved_vulnerability_ids = []
        epss_score = None
        mitigations = finding.get("FindingProviderFields", {}).get("Types")
        for mitigate in mitigations:
            mitigation += mitigate + "\n"
        mitigation += "https://docs.aws.amazon.com/guardduty/latest/ug/guardduty_finding-types-active.html"
        active = True
        if finding.get("RecordState") == "ACTIVE":
            is_Mitigated = False
            mitigated = None
        else:
            is_Mitigated = True
            if finding.get("LastObservedAt", None):
                try:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.utcnow()
        description = f"This is a GuardDuty Finding\n{finding.get('Description', '')}"
        description += f"SourceURL: {finding.get('SourceUrl', '')}\n"
        description += f"AwsAccountId: {finding.get('AwsAccountId', '')}\n"
        description += f"Region: {finding.get('Region', '')}\n"
        title_suffix = ""
        hosts = list()
        for resource in finding.get("Resources", []):
            component_name = resource.get("Type")
            if component_name in ("AwsEcrContainerImage", "AwsEc2Instance"):
                hosts.append(Endpoint(host=f"{component_name} {resource.get('Id')}"))
            if component_name == "AwsEcrContainerImage":
                details = resource.get("Details", {}).get("AwsEcrContainerImage")
                arn = resource.get("Id")
                if details:
                    impact.append(f"Image ARN: {arn}")
                    impact.append(f"Registry: {details.get('RegistryId')}")
                    impact.append(f"Repository: {details.get('RepositoryName')}")
                    impact.append(f"Image digest: {details.get('ImageDigest')}")
                title_suffix = f" - Image: {arn.split('/', 1)[1]}"  # repo-name/sha256:digest
            else:  # generic implementation
                resource_id = resource["Id"].split(":")[-1]
                impact.append(f"Resource: {resource_id}")
                title_suffix = f" - Resource: {resource_id}"
        if remediation_rec_url := finding.get("Remediation", {}).get("Recommendation", {}).get("Url"):
            references.append(remediation_rec_url)
        false_p = False
        result = Finding(
            title=f"{title}{title_suffix}",
            test=test,
            description=description,
            mitigation=mitigation,
            references="\n".join(references),
            severity=severity,
            impact="\n".join(impact),
            active=active,
            verified=False,
            false_p=false_p,
            unique_id_from_tool=finding_id,
            mitigated=mitigated,
            is_mitigated=is_Mitigated,
            static_finding=True,
            dynamic_finding=False,
            component_name=component_name,
        )
        result.unsaved_endpoints = list()
        result.unsaved_endpoints.extend(hosts)
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
