from dojo.models import Finding
from openpyxl import load_workbook


class DeepfenceThreatmapperParser(object):
    def get_scan_types(self):
        return ["Deepfence Threatmapper Report"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Deepfence Threatmapper report in XLSX format."

    def get_findings(self, filename, test):
        workbook = load_workbook(filename)
        worksheet = workbook.active
        findings = []
        headers = dict()
        first = True
        for row in worksheet.iter_rows(min_row=1, values_only=True):
            description = ""
            if first:
                first = False
                for i in range(len(row)):
                    headers[row[i]] = i
            elif headers.get("Rule Name") is not None and headers.get("Class") is not None:
                Rule_Name = row[headers["Rule Name"]]
                Class = row[headers["Class"]]
                File_Name = row[headers["File Name"]]
                Summary = row[headers["Summary"]]
                Severity = row[headers["Severity"]]
                Node_Name = row[headers["Node Name"]]
                NodeType = row[headers["NodeType"]]
                Container_Name = row[headers["Container Name"]]
                Kubernetes_Cluster_Name = row[headers["Kubernetes Cluster Name"]]
                description += "**Summary:** " + str(Summary) + "\n"
                description += "**Rule Name:** " + str(Rule_Name) + "\n"
                description += "**Class:** " + str(Class) + "\n"
                description += "**File Name:** " + str(File_Name) + "\n"
                description += "**Node Name:** " + str(Node_Name) + "\n"
                description += "**NodeType:** " + str(NodeType) + "\n"
                description += "**Container Name:** " + str(Container_Name) + "\n"
                description += "**Kubernetes Cluster Name:** " + str(Kubernetes_Cluster_Name) + "\n"
                findings.append(
                    Finding(
                        title=Rule_Name,
                        description=description,
                        file_path=File_Name,
                        severity=self.severity(Severity),
                        static_finding=False,
                        dynamic_finding=True,
                        test=test,
                    )
                )
            elif headers.get("Filename") is not None and headers.get("Content") is not None:
                Filename = row[headers["Filename"]]
                Content = row[headers["Content"]]
                Name = row[headers["Name"]]
                Rule = row[headers["Rule"]]
                Severity = row[headers["Severity"]]
                Node_Name = row[headers["Node Name"]]
                Container_Name = row[headers["Container Name"]]
                Kubernetes_Cluster_Name = row[headers["Kubernetes Cluster Name"]]
                Signature = row[headers["Signature"]]
                description += "**Filename:** " + str(Filename) + "\n"
                description += "**Name:** " + str(Name) + "\n"
                description += "**Rule:** " + str(Rule) + "\n"
                description += "**Node Name:** " + str(Node_Name) + "\n"
                description += "**Container Name:** " + str(Container_Name) + "\n"
                description += "**Kubernetes Cluster Name:** " + str(Kubernetes_Cluster_Name) + "\n"
                description += "**Content:** " + str(Content) + "\n"
                description += "**Signature:** " + str(Signature) + "\n"
                if Name is not None and Severity is not None:
                    findings.append(
                        Finding(
                            title=str(Name),
                            description=description,
                            file_path=Filename,
                            severity=self.severity(Severity),
                            static_finding=False,
                            dynamic_finding=True,
                            test=test,
                        )
                    )
            elif headers.get("@timestamp") is not None and headers.get("cve_attack_vector") is not None:
                cve_attack_vector = row[headers["cve_attack_vector"]]
                cve_caused_by_package = row[headers["cve_caused_by_package"]]
                cve_container_image = row[headers["cve_container_image"]]
                cve_container_image_id = row[headers["cve_container_image_id"]]
                cve_description = row[headers["cve_description"]]
                cve_fixed_in = row[headers["cve_fixed_in"]]
                cve_id = row[headers["cve_id"]]
                cve_link = row[headers["cve_link"]]
                cve_severity = row[headers["cve_severity"]]
                cve_overall_score = row[headers["cve_overall_score"]]
                cve_type = row[headers["cve_type"]]
                host_name = row[headers["host_name"]]
                cloud_account_id = row[headers["cloud_account_id"]]
                masked = row[headers["masked"]]
                description += "**cve_attack_vector:** " + str(cve_attack_vector) + "\n"
                description += "**cve_caused_by_package:** " + str(cve_caused_by_package) + "\n"
                description += "**cve_container_image:** " + str(cve_container_image) + "\n"
                description += "**cve_container_image_id:** " + str(cve_container_image_id) + "\n"
                description += "**cve_description:** " + str(cve_description) + "\n"
                description += "**cve_severity:** " + str(cve_severity) + "\n"
                description += "**cve_overall_score:** " + str(cve_overall_score) + "\n"
                description += "**cve_type:** " + str(cve_type) + "\n"
                description += "**host_name:** " + str(host_name) + "\n"
                description += "**cloud_account_id:** " + str(cloud_account_id) + "\n"
                description += "**masked:** " + str(masked) + "\n"
                findings.append(
                    Finding(
                        title="Threatmapper_Vuln_Report-" + cve_id,
                        description=description,
                        component_name=cve_caused_by_package,
                        severity=self.severity(cve_severity),
                        static_finding=False,
                        dynamic_finding=True,
                        mitigation=cve_fixed_in,
                        references=cve_link,
                        cve=cve_id,
                        test=test,
                    )
                )
            elif headers.get("@timestamp") is not None and headers.get("compliance_check_type") is not None:
                compliance_check_type = row[headers["compliance_check_type"]]
                count = row[headers["count"]]
                doc_id = row[headers["doc_id"]]
                host_name = row[headers["host_name"]]
                cloud_account_id = row[headers["cloud_account_id"]]
                masked = row[headers["masked"]]
                node_id = row[headers["node_id"]]
                node_name = row[headers["node_name"]]
                node_type = row[headers["node_type"]]
                status = row[headers["status"]]
                test_category = row[headers["test_category"]]
                test_desc = row[headers["test_desc"]]
                test_info = row[headers["test_info"]]
                test_number = row[headers["test_number"]]
                description += "**compliance_check_type:** " + str(compliance_check_type) + "\n"
                description += "**host_name:** " + str(host_name) + "\n"
                description += "**cloud_account_id:** " + str(cloud_account_id) + "\n"
                description += "**masked:** " + str(masked) + "\n"
                description += "**node_id:** " + str(node_id) + "\n"
                description += "**node_name:** " + str(node_name) + "\n"
                description += "**node_type:** " + str(node_type) + "\n"
                description += "**status:** " + str(status) + "\n"
                description += "**test_category:** " + str(test_category) + "\n"
                description += "**test_desc:** " + str(test_desc) + "\n"
                description += "**test_info:** " + str(test_info) + "\n"
                description += "**test_number:** " + str(test_number) + "\n"
                description += "**count:** " + str(count) + "\n"
                description += "**doc_id:** " + str(doc_id) + "\n"
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

    def severity(self, input):
        if input is None:
            return "Info"
        else:
            return input.capitalize()
