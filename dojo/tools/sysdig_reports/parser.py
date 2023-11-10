from dojo.models import Finding
from dojo.tools.sysdig_reports.sysdig_csv_parser import CSVParser

from cvss.cvss3 import CVSS3
import cvss.parser


class SysdigReportsParser(object):
    """
    Sysdig Report Importer - Runtime CSV
    """

    def get_scan_types(self):
        return ["Sysdig Vulnerability Report - Pipeline, Registry and Runtime (CSV)"]

    def get_label_for_scan_types(self, scan_type):
        return "Sysdig Vulnerability Report Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import of Sysdig Pipeline, Registry and Runtime Vulnerability Report Scans in CSV format."

    def get_findings(self, filename, test):

        if filename is None:
            return ()

        if filename.name.lower().endswith('.csv'):
            arr_data = CSVParser().parse(filename=filename)
        else:
            return ()

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
            finding.cve = row.vulnerability_id
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
                finding.description += f"###Runtime Context {row.k8s_cluster_name}"                                        f"\n - **Cluster:** {row.k8s_cluster_name}"
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
            if row.public_exploit != '':
                finding.description += f"\n - **Public Exploit:** {row.public_exploit}"

            finding.description += "\n\n###Package Details"
            if row.package_type == "os":
                finding.description += f"\n - **Package Type: {row.package_type} \\* Consider upgrading your Base OS \\***"
            else:
                finding.description += f"\n - **Package Type:** {row.package_type}"
            finding.description += f"\n - **Package Name:** {row.package_name}"
            finding.description += f"\n - **Package Version:** {row.package_version}"
            finding.description += f"\n - **In-Use:** {row.in_use}"

            if row.package_path != '':
                finding.description += f"\n - **Package Path:** {row.package_path}"
                finding.file_path = row.package_path
            if row.package_suggested_fix != '':
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
                if float(row.cvss_version) >= 3:
                    finding.cvssv3_score = row.cvss_score
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
