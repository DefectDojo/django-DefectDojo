from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData


class WazuhV4_8:
    def parse_findings(self, test, data):
        dupes = {}
        vulnerabilities = data.get("hits", {}).get("hits", [])
        for item_source in vulnerabilities:
            item = item_source.get("_source")
            vuln = item.get("vulnerability")
            cve = vuln.get("id")

            # Construct a unique key for deduplication
            dupe_key = f"{cve}-{item.get('agent', {}).get('id')}"

            if dupe_key in dupes:
                continue  # Skip if this finding has already been processed

            description = vuln.get("description")
            severity = vuln.get("severity")
            cvssv3_score = vuln.get("score").get("base") if vuln.get("score") else None
            publish_date = vuln.get("published_at").split("T")[0]
            detection_time = vuln.get("detected_at").split("T")[0]
            references = vuln.get("reference")

            # Map Wazuh severity to its equivalent in DefectDojo
            SEVERITY_MAP = {
                "Critical": "Critical",
                "High": "High",
                "Medium": "Medium",
                "Low": "Low",
                "Info": "Info",
                "Informational": "Info",
                "Untriaged": "Info",
            }
            # Get DefectDojo severity and default to "Info" if severity is not in the mapping
            severity = SEVERITY_MAP.get(severity, "Info")

            title = (
                cve + " affects (version: " + item.get("package").get("version") + ")"
            )

            find = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                references=references,
                static_finding=True,
                component_name=item.get("package").get("name"),
                component_version=item.get("package").get("version"),
                cvssv3_score=cvssv3_score,
                publish_date=publish_date,
                unique_id_from_tool=dupe_key,
                date=detection_time,
            )

            # Create endpoint from agent name
            agent_name = item.get("agent").get("name")
            if agent_name is not None:
                if settings.V3_FEATURE_LOCATIONS:
                    find.unsaved_locations = [LocationData.url(host=agent_name)]
                else:
                    find.unsaved_endpoints = [Endpoint(host=agent_name)]

            find.unsaved_vulnerability_ids = [cve]
            dupes[dupe_key] = find

        return list(dupes.values())
