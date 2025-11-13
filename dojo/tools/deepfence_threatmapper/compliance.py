from dojo.models import Finding


class DeepfenceThreatmapperCompliance:
    def get_findings(self, row, headers, test):
        if "compliance_check_type" in headers and "test_number" in headers:
            return self._parse_old_format(row, headers, test)
        if "Compliance Standard" in headers and "Control ID" in headers:
            return self._parse_new_format(row, headers, test)
        return None

    def _parse_old_format(self, row, headers, test):
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

        description = (
            f"**Compliance Check Type:** {compliance_check_type}\n"
            f"**Host Name:** {host_name}\n"
            f"**Cloud Account ID:** {cloud_account_id}\n"
            f"**Masked:** {masked}\n"
            f"**Node ID:** {node_id}\n"
            f"**Node Name:** {node_name}\n"
            f"**Node Type:** {node_type}\n"
            f"**Status:** {status}\n"
            f"**Test Category:** {test_category}\n"
            f"**Test Description:** {test_desc}\n"
            f"**Test Info:** {test_info}\n"
            f"**Test Number:** {test_number}\n"
            f"**Count:** {count}\n"
            f"**Doc ID:** {doc_id}\n"
        )

        return Finding(
            title=f"Threatmapper_Compliance_Report-{test_number}",
            description=description,
            severity=self.compliance_severity(status),
            static_finding=False,
            dynamic_finding=True,
            test=test,
        )

    def _parse_new_format(self, row, headers, test):
        compliance_standard = row[headers["Compliance Standard"]]
        status = row[headers["Status"]]
        category = row[headers["Category"]]
        description_text = row[headers["Description"]]
        info = row[headers["Info"]]
        control_id = row[headers["Control ID"]]
        node_name = row[headers["Node Name"]]
        node_type = row[headers["Node Type"]]
        remediation = row[headers["Remediation"]]
        masked = row[headers["Masked"]]

        description = (
            f"**Compliance Standard:** {compliance_standard}\n"
            f"**Status:** {status}\n"
            f"**Category:** {category}\n"
            f"**Description:** {description_text}\n"
            f"**Info:** {info}\n"
            f"**Control ID:** {control_id}\n"
            f"**Node Name:** {node_name}\n"
            f"**Node Type:** {node_type}\n"
            f"**Remediation:** {remediation}\n"
            f"**Masked:** {masked}\n"
        )

        return Finding(
            title=f"Threatmapper_Compliance_Report-{control_id}",
            description=description,
            severity=self.compliance_severity(status),
            static_finding=False,
            dynamic_finding=True,
            mitigation=remediation,
            test=test,
        )

    def compliance_severity(self, severity_input):
        if severity_input is None:
            return "Info"
        severity_input = severity_input.lower()
        if severity_input in {"pass", "info"}:
            return "Info"
        if severity_input == "warn":
            return "Medium"
        if severity_input == "fail":
            return "High"
        return "Info"
