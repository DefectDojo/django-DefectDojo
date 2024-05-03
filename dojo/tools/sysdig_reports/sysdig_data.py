import datetime


class SysdigData:

    def _map_severity(self, severity):
        severity_mapping = {
            "CRITICAL": "Critical",
            "HIGH": "High",
            "MEDIUM": "Medium",
            "LOW": "Low",
            "NEGLIGIBLE": "Informational"
        }

        return severity_mapping.get(severity, "Informational")

    """
    Data class to represent the Sysdig data extracted from sources like CSV or JSON.
    """
    def __init__(self):
        self.vulnerability_id: str = ""
        self.url: str = ""
        self.severity: str = ""
        self.package_name: str = ""
        self.package_version: str = ""
        self.package_type: str = ""
        self.package_path: str = ""
        self.image: str = ""
        self.os_name: str = ""
        self.cvss_version: float = 0
        self.cvss_score: float = 0
        self.cvss_vector: str = ""
        self.vuln_link: str = ""
        self.vuln_publish_date: str = ""
        self.vuln_fix_date: datetime.date = None
        self.vuln_fix_version: str = ""
        self.public_exploit: str = ""
        self.k8s_cluster_name: str = ""
        self.k8s_namespace_name: str = ""
        self.k8s_workload_type: str = ""
        self.k8s_workload_name: str = ""
        self.k8s_container_name: str = ""
        self.image_id: str = ""
        self.k8s_pod_count: str = 0
        self.in_use: bool = False
        self.risk_accepted: bool = False
        self.publish_date: datetime.date = None
        self.component_version: str = ""
        self.package_suggested_fix: str = ""
        self.image_type: str = ""
        self.registry_name: str = ""
        self.registry_image_repository: str = ""
        self.registry_vendor: str = ""
        self.cloud_provider_name: str = ""
        self.cloud_provider_account_id: str = ""
        self.cloud_provider_region: str = ""
