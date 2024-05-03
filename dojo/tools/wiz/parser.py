import csv
import io
import sys
from dojo.models import Finding


class WizParser(object):
    def get_scan_types(self):
        return ["Wiz Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Wiz Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Wiz scan results in csv file format."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        findings = []
        for row in reader:
            if row.get("Status").lower() == "open":
                Title = row.get("Title")
                Severity = row.get("Severity")
                Description = row.get("Description")
                Resource_Type = row.get("Resource Type")
                Resource_external_ID = row.get("Resource external ID")
                Subscription_ID = row.get("Subscription ID")
                Project_IDs = row.get("Project IDs")
                Project_Names = row.get("Project Names")
                Control_ID = row.get("Control ID")
                Resource_Name = row.get("Resource Name")
                Resource_Region = row.get("Resource Region")
                Resource_Status = row.get("Resource Status")
                Resource_Platform = row.get("Resource Platform")
                Resource_OS = row.get("Resource OS")
                Resource_original_JSON = row.get("Resource original JSON")
                Issue_ID = row.get("Issue ID")
                Resource_vertex_ID = row.get("Resource vertex ID")
                Ticket_URLs = row.get("Ticket URLs")
                Note = row.get("Note")
                Due_At = row.get("Due At")
                Subscription_Name = row.get("Subscription Name")
                Wiz_URL = row.get("Wiz URL")
                Cloud_Provider_URL = row.get("Cloud Provider URL")
                Resource_Tags = row.get("Resource Tags")
                Kubernetes_Cluster = row.get("Kubernetes Cluster")
                Kubernetes_Namespace = row.get("Kubernetes Namespace")
                Container_Service = row.get("Container Service")
                description = ""
                description += "**Description**: " + Description + "\n"
                description += "**Resource Type**: " + Resource_Type + "\n"
                description += "**external ID**: " + Resource_external_ID + "\n"
                description += "**Subscription ID**: " + Subscription_ID + "\n"
                description += "**Project IDs**: " + Project_IDs + "\n"
                description += "**Project Names**: " + Project_Names + "\n"
                description += "**Control ID**: " + Control_ID + "\n"
                description += "**Resource Name**: " + Resource_Name + "\n"
                description += "**Resource Region**: " + Resource_Region + "\n"
                description += "**Resource Status**: " + Resource_Status + "\n"
                description += "**Resource Platform**: " + Resource_Platform + "\n"
                description += "**Resource OS**: " + Resource_OS + "\n"
                description += "**original JSON**: " + Resource_original_JSON + "\n"
                description += "**Issue ID**: " + Issue_ID + "\n"
                description += "**vertex ID**: " + Resource_vertex_ID + "\n"
                description += "**Ticket URLs**: " + Ticket_URLs + "\n"
                description += "**Note**: " + Note + "\n"
                description += "**Due At**: " + Due_At + "\n"
                description += "**Subscription Name**: " + Subscription_Name + "\n"
                description += "**Wiz URL**: " + Wiz_URL + "\n"
                description += "**Provider URL**: " + Cloud_Provider_URL + "\n"
                description += "**Resource Tags**: " + Resource_Tags + "\n"
                description += "**Kubernetes Cluster**: " + Kubernetes_Cluster + "\n"
                description += "**Kubernetes Namespace**: " + Kubernetes_Namespace + "\n"
                description += "**Container Service**: " + Container_Service + "\n"
                findings.append(
                    Finding(
                        title=Title,
                        description=description,
                        severity=Severity.lower().capitalize(),
                        static_finding=False,
                        dynamic_finding=True,
                        mitigation=row.get("Remediation Recommendation"),
                        test=test,
                    )
                )
        return findings
