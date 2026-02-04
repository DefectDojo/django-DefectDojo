import hashlib

from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.url.models import URL


class WazuhV4_7:
    def parse_findings(self, test, data):
        dupes = {}
        vulnerabilities = data.get("data", {}).get("affected_items", [])
        for item in vulnerabilities:
            if (
                item["condition"] != "Package unfixed"
                and item["severity"] != "Untriaged"
            ):
                cve = item.get("cve")
                package_name = item.get("name")
                package_version = item.get("version")
                description = item.get("condition")
                severity = item.get("severity").capitalize()
                agent_ip = item.get("agent_ip")
                links = item.get("external_references")
                cvssv3_score = item.get("cvss3_score")
                publish_date = item.get("published")
                agent_name = item.get("agent_name")
                agent_ip = item.get("agent_ip")
                detection_time = item.get("detection_time").split("T")[0]

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

                references = "\n".join(links) if links else None

                title = (
                    item.get("title") + " (version: " + package_version + ")"
                )

                if agent_name:
                    dupe_key = title + cve + agent_name + package_name + package_version
                else:
                    dupe_key = title + cve + package_name + package_version
                dupe_key = hashlib.sha256(dupe_key.encode("utf-8")).hexdigest()

                if dupe_key in dupes:
                    find = dupes[dupe_key]
                else:
                    dupes[dupe_key] = True

                    find = Finding(
                        title=title,
                        test=test,
                        description=description,
                        severity=severity,
                        references=references,
                        static_finding=True,
                        component_name=package_name,
                        component_version=package_version,
                        cvssv3_score=cvssv3_score,
                        publish_date=publish_date,
                        unique_id_from_tool=dupe_key,
                        date=detection_time,
                    )

                    # in some cases the agent_ip is not the perfect way on how to identify a host. Thus prefer the agent_name, if it exists.
                    if settings.V3_FEATURE_LOCATIONS:
                        if agent_name:
                            find.unsaved_locations = [URL(host=agent_name)]
                        elif agent_ip:
                            find.unsaved_locations = [URL(host=agent_ip)]
                    # TODO: Delete this after the move to Locations
                    elif agent_name:
                        find.unsaved_endpoints = [Endpoint(host=agent_name)]
                    elif agent_ip:
                        find.unsaved_endpoints = [Endpoint(host=agent_ip)]

                    if id:
                        find.unsaved_vulnerability_ids = cve

                    dupes[dupe_key] = find
        return list(dupes.values())
