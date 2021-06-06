import json
from packageurl import PackageURL

from dojo.models import Finding


class AnchoreGrypeParser(object):
    """Anchore Grype JSON report format generated with `-o json` option.

    command: `grype defectdojo/defectdojo-django:1.13.1 -o json > many_vulns.json`
    """

    def get_scan_types(self):
        return ["anchore_grype"]

    def get_label_for_scan_types(self, scan_type):
        return "anchore_grype"

    def get_description_for_scan_types(self, scan_type):
        return "A vulnerability scanner for container images and filesystems. JSON report generated with '-o json' format"

    def get_findings(self, file, test):
        data = json.load(file)
        dupes = dict()
        for item in data.get("matches", []):
            cve = item["vulnerability"]["id"]
            severity = self._convert_severity(item["vulnerability"]["severity"])
            purl = PackageURL.from_string(item["artifact"]["purl"])
            description = ""
            description += f"\n**CVE:** {cve}"
            description += f'\n**Matcher:** {item["matchDetails"]["matcher"]}'
            description += f"\n**PURL:** {purl}"
            description += "\n**Paths:**\n"
            for match_path in item["artifact"]["locations"]:
                description += f'\n * {match_path["path"]}'

            dupe_key = cve
            if dupe_key in dupes:
                find = dupes[dupe_key]
                find.nb_occurences += 1
            else:
                dupes[dupe_key] = Finding(
                    title=f"Vulnerable component ({purl.name}:{purl.version}) {cve}",
                    description=description,
                    cve=cve,
                    severity=severity,
                    impact="No impact provided",
                    mitigation="No mitigation provided",
                    references="[{}](https://nvd.nist.gov/vuln/detail/{})".format(
                        cve, cve
                    ),
                    static_finding=True,
                    dynamic_finding=False,
                    component_name=purl.name,
                    component_version=purl.version,
                    vuln_id_from_tool=cve,
                    nb_occurences=1,
                )
        return list(dupes.values())

    def _convert_severity(self, val):
        if "Unknown" == val:
            return "Info"
        elif "Negligible" == val:
            return "Info"
        else:
            return val.title()
