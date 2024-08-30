import json
from datetime import UTC, datetime

from dojo.models import Endpoint, Finding


class AWSInspector2Parser(object):
    """
    Import AWS Inspector2 json
    """

    def get_scan_types(self):
        return ["AWS Inspector2 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Inspector2 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Inspector2 report file can be imported in JSON format (aws inspector2 list-findings)."

    def get_findings(self, file, test):
        tree = json.load(file)
        raw_findings = tree.get("findings", None)
        if not isinstance(raw_findings, list):
            msg = "Incorrect Inspector2 report format"
            raise TypeError(msg)
        findings = []
        for raw_finding in raw_findings:
            # basic fields
            aws_account = raw_finding.get("awsAccountId", "")
            finding_id = raw_finding.get("findingArn", "")
            title = raw_finding.get("title", "")
            orig_description = raw_finding.get("description", "")
            severity = self.get_severity(raw_finding.get("severity", "INFORMATIONAL"))
            # augment description
            description = f"**AWS Account**: {aws_account}\n"
            description += f"**Finding ARN**: {finding_id}\n"
            inspector_score = raw_finding.get("inspectorScore", "")
            description += f"Inspector score: {inspector_score}\n"
            discovered_at = raw_finding.get("firstObservedAt", "N/A")
            last_seen_at = raw_finding.get("lastObservedAt", "N/A")
            description += f"Discovered at: {discovered_at}\n"
            description += f"Last seen: {last_seen_at}\n"
            description += f"Original description: \n{orig_description}\n"
            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                unique_id_from_tool=finding_id,
                static_finding=True,
                dynamic_finding=False,
            )
            # set mitigation status
            if raw_finding.get("status", "ACTIVE") == "ACTIVE":
                mitigated = None
                is_mitigated = False
                active = True
            else:
                is_mitigated = True
                active = False
                if raw_finding.get("lastObservedAt", None):
                    try:
                        mitigated = datetime.strptime(
                            raw_finding.get("lastObservedAt"), "%Y-%m-%dT%H:%M:%S.%fZ"
                        )
                    except Exception:
                        mitigated = datetime.strptime(
                            raw_finding.get("lastObservedAt"), "%Y-%m-%dT%H:%M:%fZ"
                        )
                else:
                    mitigated = datetime.now(UTC)
            finding.active = active
            finding.is_mitigated = is_mitigated
            finding.mitigated = mitigated
            # EPSS
            finding.epss_score = raw_finding.get("epss", {}).get("score", None)
            # type specific details
            finding_type = raw_finding.get("type", None)
            if finding_type == "PACKAGE_VULNERABILITY":
                # extract fields
                vulnerability_details = raw_finding.get(
                    "packageVulnerabilityDetails", {}
                )
                vulnerability_id = vulnerability_details.get("vulnerabilityId", None)
                vulnerability_source = vulnerability_details.get("source", None)
                vulnerability_source_url = vulnerability_details.get("sourceUrl", None)
                vulnerability_packages = vulnerability_details.get(
                    "vulnerablePackages", []
                )
                vulnerability_packages_descriptions = []
                for vulnerability_package in vulnerability_packages:
                    package_name = vulnerability_package.get("name", "N/A")
                    package_description = f"*Vulnerable package*: {package_name}\n"
                    package_manager = vulnerability_package.get("packageManager", "N/A")
                    package_description += f"package manager: {package_manager}\n"
                    package_version = vulnerability_package.get("version", "N/A")
                    package_description += f"version: {package_version}\n"
                    package_version_fixed = vulnerability_package.get(
                        "fixedInVersion", "N/A"
                    )
                    package_description += f"fixed version: {package_version_fixed}\n"
                    package_remediation = vulnerability_package.get(
                        "remediation", "N/A"
                    )
                    package_description += f"remediation: {package_remediation}\n"
                    vulnerability_packages_descriptions.append(package_description)
                # populate fields
                finding.cve = vulnerability_id
                finding.url = vulnerability_source_url
                description += "**Additional info**\n"
                description += f"Vulnerability info from: {vulnerability_source} {vulnerability_source_url}\n"
                description += "Affected packages:\n"
                description += "\n".join(vulnerability_packages_descriptions)
                description += "\n"
                finding.description = description

            elif finding_type == "CODE_VULNERABILITY":
                # extract fields
                cwes = raw_finding.get("cwes", [])
                detector_id = raw_finding.get("detectorId", "N/A")
                detector_name = raw_finding.get("detectorName", "N/A")
                file_path_info = raw_finding.get("filePath", {})
                file_name = file_path_info.get("fileName", "N/A")
                file_path = file_path_info.get("filePath", "N/A")
                start_line = file_path_info.get("startLine", "N/A")
                end_line = file_path_info.get("endLine", "N/A")
                detector_tags = raw_finding.get("detectorTags", [])
                reference_urls = raw_finding.get("referenceUrls", [])
                rule_id = raw_finding.get("ruleId", [])
                layer_arn = raw_finding.get("sourceLambdaLayerArn", "N/A")
                # populate fields
                finding.cwe = cwes[0] if cwes else None
                finding.file_path = f"{file_path}{file_name}"
                finding.sast_source_file_path = f"{file_path}{file_name}"
                finding.line = start_line
                finding.sast_source_line = start_line
                description += "**Additional info**\n"
                description += f"CWEs: {', '.join(cwes)}\n"
                description += (
                    f"Vulnerability info from: {detector_id} {detector_name}\n"
                )
                description += f"Rule: {rule_id}\n"
                description += f"Tags: {detector_tags}\n"
                description += f"Lines: {start_line} - {end_line}\n"
                description += f"URLs: {', '.join(reference_urls)}\n"
                description += f"Lambda layer ARN: {layer_arn}\n"
                finding.description = description

            elif finding_type == "NETWORK_REACHABILITY":
                # extract fields
                network_path_info = raw_finding.get("networkPath", {})
                network_path_steps = network_path_info.get("steps", [])
                steps_descriptions = []
                for step_number, step in enumerate(network_path_steps):
                    steps_description = "steps:\n"
                    component_id = step.get("componentId", "N/A")
                    component_type = step.get("componentType", "N/A")
                    steps_description += (
                        f"{step_number}: {component_id} {component_type}"
                    )
                    steps_descriptions.append(steps_description)
                open_port_range_info = raw_finding.get("openPortRange", {})
                port_range_start = open_port_range_info.get("begin", "N/A")
                port_range_end = open_port_range_info.get("end", "N/A")
                protocol = raw_finding.get("protocol", "N/A")
                # populate fields
                description += "**Additional info**\n"
                description += f"protocol {protocol}, port range {port_range_start} - {port_range_end}"
                description += "\n".join(steps_descriptions)
                description += "\n"
            else:
                msg = "Incorrect Inspector2 report format"
                raise TypeError(msg)
            # extract endpoints
            # AWS_EC2_INSTANCE | AWS_ECR_CONTAINER_IMAGE | AWS_ECR_REPOSITORY | AWS_LAMBDA_FUNCTION
            resource_infos = raw_finding.get("resources", {})
            impact = []
            endpoints = []
            for resource_info in resource_infos:
                resource_type = resource_info.get("type", None)
                resource_id = resource_info.get("id", "N/A")
                resource_details = resource_info.get("details", {})
                resource_region = resource_info.get("region", "N/A")
                endpoint_host = f"{resource_type} - {resource_id}"
                if resource_type == "AWS_EC2_INSTANCE":
                    endpoint_host = resource_id
                    ec2_instance_details = resource_details.get("awsEc2Instance", None)
                    if ec2_instance_details:
                        impact.append(f"ARN: {resource_id}")
                        impact.append(
                            f"Image ID: {ec2_instance_details.get('imageId', 'N/A')}"
                        )
                        impact.append(
                            f"IPv4 address: {ec2_instance_details.get('ipV4Addresses', 'N/A')}"
                        )
                        impact.append(
                            f"Subnet: {ec2_instance_details.get('subnetId', 'N/A')}"
                        )
                        impact.append(
                            f"VPC: {ec2_instance_details.get('vpcId', 'N/A')}"
                        )
                        impact.append(f"Region: {resource_region}")
                        impact.append(f"AWS Account: {aws_account}")
                        impact.append(
                            f"Launched at: {ec2_instance_details.get('launchedAt', 'N/A')}"
                        )
                        impact.append("---")
                elif resource_type == "AWS_ECR_CONTAINER_IMAGE":
                    image_id = (
                        resource_id.split("repository/")[1]
                        .replace("sha256:", "")
                        .replace("/", "-")
                    )
                    endpoint_host = image_id
                    ecr_image_details = resource_details.get(
                        "awsEcrContainerImage", None
                    )
                    if ecr_image_details:
                        impact.append(f"ARN: {resource_id}")
                        impact.append(
                            f"Registry: {ecr_image_details.get('registry', 'N/A')}"
                        )
                        impact.append(
                            f"Repository: {ecr_image_details.get('repositoryName', 'N/A')}"
                        )
                        impact.append(
                            f"Hash: {ecr_image_details.get('imageHash', 'N/A')}"
                        )
                        impact.append(
                            f"Author: {ecr_image_details.get('author', 'N/A')}"
                        )
                        impact.append(
                            f"Pushed at: {ecr_image_details.get('pushedAt', 'N/A')}"
                        )
                        impact.append("---")
                elif resource_type == "AWS_ECR_REPOSITORY":
                    # no corresponding
                    # key present in
                    # https://docs.aws.amazon.com/inspector/v2/APIReference/API_ResourceDetails.html
                    pass
                elif resource_type == "AWS_LAMBDA_FUNCTION":
                    lambda_id = (
                        resource_id.split("function:")[1]
                        .replace(":", "-")
                        .replace("/", "-")
                    )
                    endpoint_host = lambda_id
                    lambda_details = resource_details.get("awsLambdaFunction", None)
                    if lambda_details:
                        impact.append(f"ARN: {resource_id}")
                        impact.append(
                            f"Name: {lambda_details.get('functionName', 'N/A')}"
                        )
                        impact.append(
                            f"Version: {lambda_details.get('version', 'N/A')}"
                        )
                        impact.append(
                            f"Runtime: {lambda_details.get('runtime', 'N/A')}"
                        )
                        impact.append(
                            f"Hash: {lambda_details.get('codeSha256', 'N/A')}"
                        )
                        impact.append(
                            f"Pushed at: {lambda_details.get('lastModifiedAt', 'N/A')}"
                        )
                else:
                    msg = "Incorrect Inspector2 report format"
                    raise TypeError(msg)
                endpoints.append(Endpoint(host=endpoint_host))
            finding.impact = "\n".join(impact)
            finding.unsaved_endpoints = []
            finding.unsaved_endpoints.extend(endpoints)
            findings.append(finding)

        return findings

    def get_severity(self, severity_string):
        if severity_string == "UNTRIAGED":
            severity_string = "INFORMATIONAL"
        return severity_string.title()
