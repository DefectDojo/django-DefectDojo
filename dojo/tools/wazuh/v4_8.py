import hashlib

from dojo.models import Finding


class WazuhV4_8:
    def parse_findings(self, test, data):
        dupes = {}
        vulnerabilities = data.get("hits", {}).get("hits", [])
        for item_source in vulnerabilities:
            item = item_source.get("_source")
            vuln = item.get("vulnerability")
            cve = vuln.get("id")
            description = vuln.get("description")
            description += "\nAgent id:" + item.get("agent").get("id")
            description += "\nAgent name:" + item.get("agent").get("name")
            severity = vuln.get("severity")
            cvssv3_score = vuln.get("score").get("base")
            publish_date = vuln.get("published_at").split("T")[0]
            agent_id = item.get("agent").get("id")
            detection_time = vuln.get("detected_at").split("T")[0]

            references = vuln.get("reference")

            title = (
                cve + " affects (version: " + item.get("package").get("version") + ")"
            )

            dupe_key = title + agent_id + description
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
                component_name=item.get("package").get("name"),
                component_version=item.get("package").get("version"),
                cvssv3_score=cvssv3_score,
                publish_date=publish_date,
                unique_id_from_tool=dupe_key,
                date=detection_time,
            )
            find.unsaved_vulnerability_ids = cve
            dupes[dupe_key] = find
        return list(dupes.values())
