from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData


class DeepfenceThreatmapperSecret:
    def get_findings(self, row, headers, test):
        if "Name" in headers and "Signature" in headers:
            return self._parse_old_format(row, headers, test)
        if "Content Starting Index" in headers and "Masked" in headers:
            return self._parse_new_format(row, headers, test)
        return None

    def _parse_old_format(self, row, headers, test):
        description = ""
        Filename = row[headers["Filename"]]
        Content = row[headers["Content"]]
        Name = row[headers["Name"]]
        Rule = row[headers["Rule"]]
        Severity = row[headers["Severity"]]
        Node_Name = row[headers["Node Name"]]
        Container_Name = row[headers["Container Name"]]
        Kubernetes_Cluster_Name = row[headers["Kubernetes Cluster Name"]]
        Signature = row[headers["Signature"]]
        description += f"**Filename:** {Filename}\n"
        description += f"**Name:** {Name}\n"
        description += f"**Rule:** {Rule}\n"
        description += f"**Node Name:** {Node_Name}\n"
        description += f"**Container Name:** {Container_Name}\n"
        description += f"**Kubernetes Cluster Name:** {Kubernetes_Cluster_Name}\n"
        description += f"**Content:** {Content}\n"
        description += f"**Signature:** {Signature}\n"
        if Name and Severity:
            finding = Finding(
                title=str(Name),
                description=description,
                file_path=Filename,
                severity=self.severity(Severity),
                static_finding=False,
                dynamic_finding=True,
                test=test,
            )
            if settings.V3_FEATURE_LOCATIONS and Filename:
                finding.unsaved_locations.append(
                    LocationData.code(file_path=Filename, line=None),
                )
            return finding
        return None

    def _parse_new_format(self, row, headers, test):
        description = ""
        Filename = row[headers["Filename"]]
        Content = row[headers["Content"]]
        Rule = row[headers["Rule"]]
        Severity = row[headers["Severity"]]
        Content_Starting_Index = row[headers["Content Starting Index"]]
        Node_Name = row[headers["Node Name"]]
        Node_Type = row[headers["Node Type"]]
        Kubernetes_Cluster_Name = row[headers["Kubernetes Cluster Name"]]
        Masked = row[headers["Masked"]]
        description += f"**Filename:** {Filename}\n"
        description += f"**Rule:** {Rule}\n"
        description += f"**Node Name:** {Node_Name}\n"
        description += f"**Node Type:** {Node_Type}\n"
        description += f"**Kubernetes Cluster Name:** {Kubernetes_Cluster_Name}\n"
        description += f"**Content:** {Content}\n"
        description += f"**Content Starting Index:** {Content_Starting_Index}\n"
        description += f"**Masked:** {Masked}\n"
        title = f"{Rule} in {Filename}" if Rule else "Secret Finding"
        if Severity:
            finding = Finding(
                title=title,
                description=description,
                file_path=Filename,
                severity=self.severity(Severity),
                static_finding=False,
                dynamic_finding=True,
                test=test,
            )
            if settings.V3_FEATURE_LOCATIONS and Filename:
                finding.unsaved_locations.append(
                    LocationData.code(file_path=Filename, line=None),
                )
            return finding
        return None

    def severity(self, severity_input):
        if severity_input is None:
            return "Info"
        return severity_input.capitalize()
