import hashlib

from dojo.models import Finding


class WazuhV4_8:
    def parse_findings(self, test, data):
        dupes = {}
        vulnerabilities = data.get("hits", {}).get("hits", [])
        for item in vulnerabilities:
            vuln = item.get("vulnerability")
            cve = vuln.get("id")
            description = vuln.get("description")
            severity = vuln.get("severity")
            cvssv3_score = vuln.get("score").get("base")
            publish_date = vuln.get("published_at").split("T")[0]
            agent_name = item.get("agent").get("name")
            agent_id = item.get("agent").get("id")
            detection_time = vuln.get("detected_at").split("T")[0]

            references = vuln.get("reference")

            title = (
                cve + " (agent_id: " + agent_id + ")"
            )

            dupe_key = title + agent_name + description
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
                cvssv3_score=cvssv3_score,
                publish_date=publish_date,
                unique_id_from_tool=dupe_key,
                date=detection_time,
            )
        dupes[dupe_key] = find
        return list(dupes.values())
