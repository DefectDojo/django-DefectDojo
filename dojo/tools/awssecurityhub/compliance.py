import datetime

from dojo.models import Finding


class Compliance:
    def get_item(self, finding: dict, test):
        finding_id = finding.get("Id", "")
        title = finding.get("Title", "")
        severity = finding.get("Severity", {}).get("Label", "INFORMATIONAL").title()
        resource_arns = [arn for resource in finding.get("Resources", [])
                                if (arn := resource.get("Id"))]
        mitigation = ""
        impact = []
        references = []
        unsaved_vulnerability_ids = []
        epss_score = None
        mitigation = finding.get("Remediation", {}).get("Recommendation", {}).get("Text", "")
        mitigation += "\n" + finding.get("Remediation", {}).get("Recommendation", {}).get("Url", "")
        description = "This is a Security Hub Finding \n" + finding.get("Description", "") + "\n"
        description += f"**AWS Finding ARN:** {finding_id}\n"
        description += f"**Resource IDs:** {', '.join(set(resource_arns))}\n"
        description += f"**AwsAccountId:** {finding.get('AwsAccountId', '')}\n"
        if finding.get("Region"):
            description += f"**Region:** {finding.get('Region', '')}\n"
        description += f"**Generator ID:** {finding.get('GeneratorId', '')}\n"
        if finding.get("Compliance", {}).get("Status", "PASSED") == "PASSED":
            is_Mitigated = True
            active = False
            if finding.get("LastObservedAt"):
                try:
                    mitigated = datetime.datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ")
                except Exception:
                    mitigated = datetime.datetime.strptime(finding.get("LastObservedAt"), "%Y-%m-%dT%H:%M:%fZ")
            else:
                mitigated = datetime.datetime.now(datetime.UTC)
        else:
            mitigated = None
            is_Mitigated = False
            active = True
        title_suffix = ""
        for resource in finding.get("Resources", []):
            component_name = resource.get("Type")
            if component_name == "AwsEcrContainerImage":
                details = resource.get("Details", {}).get("AwsEcrContainerImage")
                arn = resource.get("Id")
                if details:
                    impact.extend((
                        f"Image ARN: {arn}",
                        f"Registry: {details.get('RegistryId')}",
                        f"Repository: {details.get('RepositoryName')}",
                        f"Image digest: {details.get('ImageDigest')}",
                        f"Image tags: {','.join(details.get('ImageTags', []))}",
                    ))
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
        if epss_score is not None:
            result.epss_score = epss_score
        # Add the unsaved vulnerability ids
        result.unsaved_vulnerability_ids = unsaved_vulnerability_ids
        return result
