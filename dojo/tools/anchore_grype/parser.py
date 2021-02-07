import json

from dojo.models import Finding


class AnchoreGrypeScanParser(object):
    def get_findings(self, file, test):
        tree = json.load(file)
        dupes = dict()
        for item in tree.get("matches"):
            vulnerability = item.get("vulnerability")
            artifact = item.get("artifact")
            if vulnerability is None or artifact is None:
                continue

            cve = vulnerability.get("id")
            title = (
                vulnerability.get("id")
                + " - "
                + artifact.get("name")
                + " ("
                + artifact.get("version")
                + ")"
            )

            # Finding details information
            findingdetail = "\n\n".join(
                [
                    "**Artifact name:** " + artifact.get("name"),
                    "**Artifact version:** " + artifact.get("version"),
                    "**Artifact type:** " + artifact.get("type"),
                ]
            )

            references = cve

            severity = vulnerability.get("severity")
            if severity == "Negligible" or severity == "Unknown":
                severity = "Info"

            dupe_key = vulnerability.get("id")
            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    cve=cve,
                    description=findingdetail,
                    severity=severity,
                    numerical_severity=Finding.get_numerical_severity(severity),
                    mitigation="N/A",
                    impact="No impact provided",
                    references=references,
                    component_name=artifact.get("name"),
                    component_version=artifact.get("version"),
                    static_finding=True,
                    dynamic_finding=False,
                    vuln_id_from_tool=vulnerability.get("id"),
                )

                dupes[dupe_key] = find

        return list(dupes.values())
