import csv
import io
import json

import cvss.parser
from cvss.cvss3 import CVSS3

from dojo.models import Finding
from dojo.tools.sysdig_common.sysdig_data import SysdigData


class SysdigReportsParser:

    """Sysdig Report Importer - Runtime CSV"""

    def get_scan_types(self):
        return ["Sysdig Vulnerability Report"]

    def get_label_for_scan_types(self, scan_type):
        return "Sysdig Vulnerability Report Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import of Sysdig Pipeline, Registry and Runtime Vulnerability Report Scans in CSV format or a Sysdig UI JSON Report"

    def get_findings(self, filename, test):
        if filename is None:
            return ()
        if filename.name.lower().endswith(".csv"):
            arr_data = self.load_csv(filename=filename)
            return self.parse_csv(arr_data=arr_data, test=test)
        if filename.name.lower().endswith(".json"):
            scan_data = filename.read()
            try:
                data = json.loads(str(scan_data, "utf-8"))
            except Exception:
                data = json.loads(scan_data)

                if "data" in data:
                    return self.parse_json(data=data, test=test)

                if "result" in data:
                    msg = "JSON file is not in the expected format, it looks like a Sysdig CLI report."
                else:
                    msg = "JSON file is not in the expected format, expected data element"
                raise ValueError(msg)
        return ()

    def parse_json(self, data, test):
        vulnerability = data.get("data", None)
        if not vulnerability:
            return []
        findings = []
        for item in vulnerability:
            imageId = item.get("imageId", "")
            imagePullString = item.get("imagePullString", "")
            osName = item.get("osName", "")
            k8sClusterName = item.get("k8sClusterName", "")
            k8sNamespaceName = item.get("k8sNamespaceName", "")
            k8sWorkloadType = item.get("k8sWorkloadType", "")
            k8sWorkloadName = item.get("k8sWorkloadName", "")
            k8sPodContainerName = item.get("k8sPodContainerName", "")
            vulnName = item.get("vulnName", "")
            vulnSeverity = item.get("vulnSeverity", "")
            vulnLink = item.get("vulnLink", "")
            vulnCvssVersion = item.get("vulnCvssVersion", "")
            vulnCvssScore = item.get("vulnCvssScore", "")
            vulnCvssVector = item.get("vulnCvssVector", "")
            vulnDisclosureDate = item.get("vulnDisclosureDate", "")
            vulnSolutionDate = item.get("vulnSolutionDate", "")
            vulnExploitable = item.get("vulnExploitable", "")
            vulnFixAvailable = item.get("vulnFixAvailable", "")
            vulnFixVersion = item.get("vulnFixVersion", "")
            packageName = item.get("packageName", "")
            packageType = item.get("packageType", "")
            packagePath = item.get("packagePath", "")
            packageVersion = item.get("packageVersion", "")
            packageSuggestedFix = item.get("packageSuggestedFix", "")
            k8sPodCount = item.get("k8sPodCount", "")

            description = ""
            description += "imageId: " + imageId + "\n"
            description += "imagePullString: " + imagePullString + "\n"
            description += "osName: " + osName + "\n"
            description += "k8sClusterName: " + k8sClusterName + "\n"
            description += "k8sNamespaceName: " + k8sNamespaceName + "\n"
            description += "k8sWorkloadType: " + k8sWorkloadType + "\n"
            description += "k8sWorkloadName: " + k8sWorkloadName + "\n"
            description += "k8sPodContainerName: " + k8sPodContainerName + "\n"
            description += "vulnCvssVersion: " + vulnCvssVersion + "\n"
            description += "vulnCvssScore: " + str(vulnCvssScore) + "\n"
            description += "vulnCvssVector: " + vulnCvssVector + "\n"
            description += "vulnDisclosureDate: " + vulnDisclosureDate + "\n"
            description += "vulnSolutionDate: " + vulnSolutionDate + "\n"
            description += "vulnExploitable: " + str(vulnExploitable) + "\n"
            description += "packageName: " + packageName + "\n"
            description += "packageType: " + packageType + "\n"
            description += "packagePath: " + packagePath + "\n"
            description += "packageVersion: " + packageVersion + "\n"
            description += "packageSuggestedFix: " + packageSuggestedFix + "\n"
            description += "k8sPodCount: " + str(k8sPodCount) + "\n"

            mitigation = ""
            mitigation += "vulnFixAvailable: " + str(vulnFixAvailable) + "\n"
            mitigation += "vulnFixVersion: " + vulnFixVersion + "\n"
            mitigation += "suggestedFix: " + packageSuggestedFix + "\n"

            find = Finding(
                title=vulnName + "_" + vulnFixVersion,
                test=test,
                description=description,
                severity=vulnSeverity,
                mitigation=mitigation,
                static_finding=True,
                references=vulnLink,
                component_name=packageName,
                component_version=packageVersion,
            )
            if vulnName != "":
                find.unsaved_vulnerability_ids = []
                find.unsaved_vulnerability_ids.append(vulnName)
            findings.append(find)
        return findings

    def parse_csv(self, arr_data, test):
        if len(arr_data) == 0:
            return ()
        sysdig_report_findings = []
        for row in arr_data:
            finding = Finding(test=test)
            # Generate finding
            if row.k8s_cluster_name != "":
                finding.title = f"{row.k8s_cluster_name} - {row.k8s_namespace_name} - {row.package_name} - {row.vulnerability_id}"
            else:
                finding.title = f"{row.vulnerability_id} - {row.package_name}"
            finding.vuln_id_from_tool = row.vulnerability_id
            finding.unsaved_vulnerability_ids = []
            finding.unsaved_vulnerability_ids.append(row.vulnerability_id)
            finding.severity = row.severity
            # Set Component Version
            finding.component_name = row.package_name
            finding.component_version = row.package_version
            # Set some finding tags
            tags = []
            if row.k8s_cluster_name != "":
                tags.append("Cluster: " + row.k8s_cluster_name)
            if row.k8s_namespace_name != "":
                tags.append("Namespace: " + row.k8s_namespace_name)
            if row.k8s_workload_name != "":
                tags.append("WorkloadName: " + row.k8s_workload_name)
            if row.package_name != "":
                tags.append("PackageName: " + row.package_name)
            if row.package_version != "":
                tags.append("PackageVersion: " + row.package_version)
            if row.k8s_cluster_name != "":
                tags.append("InUse: " + str(row.in_use))
            if row.vulnerability_id != "":
                tags.append("VulnId: " + row.vulnerability_id)
            finding.tags = tags
            if row.k8s_cluster_name != "":
                finding.dynamic_finding = True
                finding.static_finding = False
                finding.description += f"###Runtime Context {row.k8s_cluster_name}\n - **Cluster:** {row.k8s_cluster_name}"
                finding.description += f"\n - **Namespace:** {row.k8s_namespace_name}"
                finding.description += f"\n - **Workload Name:** {row.k8s_workload_name} "
                finding.description += f"\n - **Workload Type:** {row.k8s_workload_type} "
                finding.description += f"\n - **Container Name:** {row.k8s_container_name}"
            else:
                finding.dynamic_finding = False
                finding.static_finding = True
            if row.cloud_provider_name != "" or row.cloud_provider_name != "" or row.cloud_provider_region != "":
                finding.description += "\n\n###Cloud Details"
            if row.cloud_provider_name != "":
                finding.description += f"\n - **Cloud Provider Name:** {row.cloud_provider_name}"
            if row.cloud_provider_account_id != "":
                finding.description += f"\n - **Cloud Provider Account Id:** {row.cloud_provider_account_id}"
            if row.cloud_provider_region != "":
                finding.description += f"\n - **Cloud Provider Region:** {row.cloud_provider_region}"
            if row.registry_name != "" or row.registry_image_repository != "" or row.registry_vendor != "":
                finding.description += "\n\n###Registry Details"
            if row.registry_name != "":
                finding.description += f"\n - **Registry Name:** {row.registry_name}"
            if row.registry_image_repository != "":
                finding.description += f"\n - **Registry Image Repository:** {row.registry_image_repository}"
            if row.registry_vendor != "":
                finding.description += f"\n - **Registry Vendor:** {row.registry_vendor}"
            finding.description += "\n\n###Vulnerability Details"
            finding.description += f"\n - **Vulnerability ID:** {row.vulnerability_id}"
            finding.description += f"\n - **Vulnerability Link:** {row.vuln_link}"
            finding.description += f"\n - **Severity:** {row.severity}"
            finding.description += f"\n - **Publish Date:** {row.vuln_publish_date}"
            finding.description += f"\n - **CVSS Version:** {row.cvss_version}"
            finding.description += f"\n - **CVSS Vector:** {row.cvss_vector}"
            if row.public_exploit != "":
                finding.description += f"\n - **Public Exploit:** {row.public_exploit}"
            finding.description += "\n\n###Package Details"
            if row.package_type == "os":
                finding.description += f"\n - **Package Type: {row.package_type} \\* Consider upgrading your Base OS \\***"
            else:
                finding.description += f"\n - **Package Type:** {row.package_type}"
            finding.description += f"\n - **Package Name:** {row.package_name}"
            finding.description += f"\n - **Package Version:** {row.package_version}"
            finding.description += f"\n - **In-Use:** {row.in_use}"
            if row.package_path != "":
                finding.description += f"\n - **Package Path:** {row.package_path}"
                finding.file_path = row.package_path
            if row.package_suggested_fix != "":
                finding.mitigation = f"Package suggested fix version: {row.package_suggested_fix}"
                finding.description += f"\n - **Package suggested fix version:** {row.package_suggested_fix}"
                if row.package_type == "os":
                    finding.mitigation += "\n\\*** Consider upgrading your Base OS \\***"
            finding.description += "\n\n###Image Details"
            finding.description += f"\n - **Image Name:** {row.image}"
            finding.description += f"\n - **Image OS:** {row.os_name}"
            finding.description += f"\n - **Image ID:** {row.image_id}"
            # If we have registry information
            if row.registry_name != "":
                finding.description += f"\n - **Registry Name:** {row.registry_name}"
                finding.description += f"\n - **Registy Image Repository:** {row.registry_image_repository}"
            try:
                if float(row.cvss_version) >= 3 and float(row.cvss_version) < 4:
                    finding.cvssv3_score = float(row.cvss_score)
                    vectors = cvss.parser.parse_cvss_from_text(row.cvss_vector)
                    if len(vectors) > 0 and isinstance(vectors[0], CVSS3):
                        finding.cvss = vectors[0].clean_vector()
            except ValueError:
                continue
            finding.risk_accepted = row.risk_accepted
            # Set reference
            if row.vuln_link != "":
                finding.references = row.vuln_link
                finding.url = row.vuln_link

            # finally, Add finding to list
            sysdig_report_findings.append(finding)
        return sysdig_report_findings

    def load_csv(self, filename) -> SysdigData:

        if filename is None:
            return ()

        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        reader = csv.DictReader(io.StringIO(content), delimiter=",", quotechar='"')

        # normalise on lower case for consistency
        reader.fieldnames = [name.lower() for name in reader.fieldnames]

        csvarray = []

        for row in reader:
            # Compare headers to values.
            if len(row) != len(reader.fieldnames):
                msg = f"Number of fields in row ({len(row)}) does not match number of headers ({len(reader.fieldnames)})"
                raise ValueError(msg)

            # Check for a CVE value to being with
            if not row[reader.fieldnames[0]].startswith("CVE"):
                msg = f"Expected 'CVE' at the start but got: {row[reader.fieldnames[0]]}"
                raise ValueError(msg)

            csvarray.append(row)

        if "cve id" in reader.fieldnames:
            msg = "Unknown CSV format: CVE ID column found, looks like a SysDig CLI Report"
            raise ValueError(msg)

        if "vulnerability id" not in reader.fieldnames:
            msg = "Unknown CSV format: expected Vulnerability ID column"
            raise ValueError(msg)

        arr_csv_data = []

        for row in csvarray:

            csv_data_record = SysdigData()
            if "vulnerability id" in reader.fieldnames:
                # Vulnerability Engine Format
                csv_data_record.vulnerability_id = row.get("vulnerability id", "")
                csv_data_record.severity = csv_data_record._map_severity(row.get("severity").upper())
                csv_data_record.package_name = row.get("package name", "")
                csv_data_record.package_version = row.get("package version", "")
                csv_data_record.package_type = row.get("package type", "")
                csv_data_record.package_path = row.get("package path", "")
                csv_data_record.image = row.get("image", "")
                csv_data_record.os_name = row.get("os name", "")
                csv_data_record.cvss_version = row.get("cvss version", "")
                csv_data_record.cvss_score = row.get("cvss score", "")
                csv_data_record.cvss_vector = row.get("cvss vector", "")
                csv_data_record.vuln_link = row.get("vuln link", "")
                csv_data_record.vuln_publish_date = row.get("vuln publish date", "")
                csv_data_record.vuln_fix_date = row.get("vuln fix date", "")
                csv_data_record.vuln_fix_version = row.get("fix version", "")
                csv_data_record.public_exploit = row.get("public exploit", "")
                csv_data_record.k8s_cluster_name = row.get("k8s cluster name", "")
                csv_data_record.k8s_namespace_name = row.get("k8s namespace name", "")
                csv_data_record.k8s_workload_type = row.get("k8s workload type", "")
                csv_data_record.k8s_workload_name = row.get("k8s workload name", "")
                csv_data_record.k8s_container_name = row.get("k8s container name", "")
                csv_data_record.image_id = row.get("image id", "")
                csv_data_record.k8s_pod_count = row.get("k8s pod count", "")
                csv_data_record.package_suggested_fix = row.get("package suggested fix", "")
                csv_data_record.in_use = row.get("in use", "") == "TRUE"
                csv_data_record.risk_accepted = row.get("risk accepted", "") == "TRUE"
                csv_data_record.registry_name = row.get("registry name", "")
                csv_data_record.registry_image_repository = row.get("registry image repository", "")
                csv_data_record.cloud_provider_name = row.get("cloud provider name", "")
                csv_data_record.cloud_provider_account_id = row.get("cloud provider account ID", "")
                csv_data_record.cloud_provider_region = row.get("cloud provider region", "")
                csv_data_record.registry_vendor = row.get("registry vendor", "")

                arr_csv_data.append(csv_data_record)

        return arr_csv_data
