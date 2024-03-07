import csv
import sys
import io
from dojo.models import Finding


class DeepfenceThreatmapperParser(object):
    def get_scan_types(self):
        return ["Deepfence Threatmapper Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Deepfence Threatmapper report in csv format."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        findings = []
        for row in reader:
            description = ""
            if row.get("Rule Name") and row.get("Class"):
                Rule_Name = row.get("Rule Name")
                Class = row.get("Class")
                File_Name = row.get("File Name")
                Summary = row.get("Summary")
                Severity = row.get("Severity")
                Node_Name = row.get("Node Name")
                NodeType = row.get("NodeType")
                Container_Name = row.get("Container Name")
                Kubernetes_Cluster_Name = row.get("Kubernetes Cluster Name")
                description += "**Summary: **" + Summary + "\n"
                description += "**Rule Name: **" + Rule_Name + "\n"
                description += "**Class: **" + Class + "\n"
                description += "**File Name: **" + File_Name + "\n"
                description += "**Node Name: **" + Node_Name + "\n"
                description += "**NodeType: **" + NodeType + "\n"
                description += "**Container Name: **" + Container_Name + "\n"
                description += "**Kubernetes Cluster Name: **" + Kubernetes_Cluster_Name + "\n"
                findings.append(
                    Finding(
                        title=Rule_Name,
                        description=description,
                        file_path=File_Name,
                        severity=Severity.capitalize(),
                        static_finding=False,
                        dynamic_finding=True,
                        test=test,
                    )
                )
            elif row.get("Filename") and row.get("Content"):
                Filename = row.get("Filename")
                Content = row.get("Content")
                Name = row.get("Name")
                Rule = row.get("Rule")
                Severity = row.get("Severity")
                Node_Name = row.get("Node Name")
                Container_Name = row.get("Container Name")
                Kubernetes_Cluster_Name = row.get("Kubernetes Cluster Name")
                Signature = row.get("Signature")
                description += "**Filename: **" + Filename + "\n"
                description += "**Name: **" + Name + "\n"
                description += "**Rule: **" + Rule + "\n"
                description += "**Node Name: **" + Node_Name + "\n"
                description += "**Container Name: **" + Container_Name + "\n"
                description += "**Kubernetes Cluster Name: **" + Kubernetes_Cluster_Name + "\n"
                description += "**Content: **" + Content + "\n"
                description += "**Signature: **" + Signature + "\n"
                findings.append(
                    Finding(
                        title=Name,
                        description=description,
                        file_path=Filename,
                        severity=Severity.capitalize(),
                        static_finding=False,
                        dynamic_finding=True,
                        test=test,
                    )
                )
            elif row.get("@timestamp") and row.get("cve_attack_vector"):
                cve_attack_vector = row.get("cve_attack_vector")
                cve_caused_by_package = row.get("cve_caused_by_package")
                cve_container_image = row.get("cve_container_image")
                scan_id = row.get("scan_id")
                cve_container_image_id = row.get("cve_container_image_id")
                cve_cvss_score = row.get("cve_cvss_score")
                cve_description = row.get("cve_description")
                cve_fixed_in = row.get("cve_fixed_in")
                cve_id = row.get("cve_id")
                cve_link = row.get("cve_link")
                cve_severity = row.get("cve_severity")
                cve_overall_score = row.get("cve_overall_score")
                cve_type = row.get("cve_type")
                host_name = row.get("host_name")
                cloud_account_id = row.get("cloud_account_id")
                masked = row.get("masked")
                description += "**cve_attack_vector: **" + cve_attack_vector + "\n"
                description += "**cve_caused_by_package: **" + cve_caused_by_package + "\n"
                description += "**cve_container_image: **" + cve_container_image + "\n"
                description += "**cve_container_image_id: **" + cve_container_image_id + "\n"
                description += "**cve_description: **" + cve_description + "\n"
                description += "**cve_severity: **" + cve_severity + "\n"
                description += "**cve_overall_score: **" + cve_overall_score + "\n"
                description += "**cve_type: **" + cve_type + "\n"
                description += "**host_name: **" + host_name + "\n"
                description += "**cloud_account_id: **" + cloud_account_id + "\n"
                description += "**masked: **" + masked + "\n"
                description += "**scan_id: **" + scan_id + "\n"
                findings.append(
                    Finding(
                        title="Threatmapper_Vuln_Report-" + cve_id,
                        description=description,
                        component_name=cve_caused_by_package,
                        cvssv3_score=cve_cvss_score,
                        severity=cve_severity.capitalize(),
                        static_finding=False,
                        dynamic_finding=True,
                        mitigation=cve_fixed_in,
                        references=cve_link,
                        cve=cve_id,
                        test=test,
                    )
                )
            elif row.get("@timestamp") and row.get("compliance_check_type"):
                compliance_check_type = row.get("compliance_check_type")
                count = row.get("count")
                doc_id = row.get("doc_id")
                host_name = row.get("host_name")
                cloud_account_id = row.get("cloud_account_id")
                masked = row.get("masked")
                node_id = row.get("node_id")
                node_name = row.get("node_name")
                node_type = row.get("node_type")
                status = row.get("status")
                test_category = row.get("test_category")
                test_desc = row.get("test_desc")
                test_info = row.get("test_info")
                test_number = row.get("test_number")
                description += "**compliance_check_type: **" + compliance_check_type + "\n"
                description += "**host_name: **" + host_name + "\n"
                description += "**cloud_account_id: **" + cloud_account_id + "\n"
                description += "**masked: **" + masked + "\n"
                description += "**node_id: **" + node_id + "\n"
                description += "**node_name: **" + node_name + "\n"
                description += "**node_type: **" + node_type + "\n"
                description += "**status: **" + status + "\n"
                description += "**test_category: **" + test_category + "\n"
                description += "**test_desc: **" + test_desc + "\n"
                description += "**test_info: **" + test_info + "\n"
                description += "**test_number: **" + test_number + "\n"
                description += "**count: **" + count + "\n"
                description += "**doc_id: **" + doc_id + "\n"
                findings.append(
                    Finding(
                        title="Threatmapper_Compliance_Report-" + test_number,
                        description=description,
                        severity=self.compliance_severity(status),
                        static_finding=False,
                        dynamic_finding=True,
                        test=test,
                    )
                )
        return findings

    def compliance_severity(self, input):
        if input == "pass":
            output = "Info"
        elif input == "info":
            output = "Info"
        elif input == "warn":
            output = "Medium"
        else:
            output = "Info"
        return output
