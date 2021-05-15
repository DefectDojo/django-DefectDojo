import json
import logging
import urllib

from dojo.models import Finding

logger = logging.getLogger(__name__)


class SafetyParser(object):

    def get_scan_types(self):
        return ["Safety Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Safety Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Safety scan (--json) output file can be imported in JSON format."

    def get_safetydb(self):
        """Grab Safety DB for CVE lookup"""
        url = "https://raw.githubusercontent.com/pyupio/safety-db/master/data/insecure_full.json"
        try:
            response = urllib.request.urlopen(url)
            return json.load(response)
        except urllib.error.URLError as e:
            logger.warn("Error Message: %s", e)
            logger.warn("Could not resolve %s. Fallback is using the offline version from dojo/tools/safety/insecure_full.json.", url)
            with open("dojo/tools/safety/insecure_full.json", "r") as insecure_full:
                return json.load(insecure_full)

    def get_findings(self, json_output, test):
        safety_db = self.get_safetydb()

        tree = json.load(json_output)

        items = {}
        for node in tree:
            item_node = {
                'package': str(node[0]),
                'affected': str(node[1]),
                'installed': str(node[2]),
                'description': str(node[3]),
                'id': str(node[4])
            }
            severity = 'Medium'  # Because Safety doesn't include severity rating
            cve = None
            for a in safety_db[item_node['package']]:
                if a['id'] == 'pyup.io-' + item_node['id']:
                    if a['cve']:
                        cve = a['cve']
            title = item_node['package'] + " (" + item_node['affected'] + ")"

            finding = Finding(title=title + " | " + cve if cve else title,
                            test=test,
                            severity=severity,
                            description="**Description:** " + item_node['description'] +
                                        "\n**Vulnerable Package:** " + item_node['package'] +
                                        "\n**Installed Version:** " + item_node['installed'] +
                                        "\n**Vulnerable Versions:** " + item_node['affected'] +
                                        "\n**CVE:** " + (cve or "N/A") +
                                        "\n**ID:** " + item_node['id'],
                            cve=cve,
                            cwe=1035,  # Vulnerable Third Party Component
                            mitigation="No mitigation provided",
                            references="No reference provided",
                            false_p=False,
                            duplicate=False,
                            out_of_scope=False,
                            mitigated=None,
                            impact="No impact provided",
                            component_name=item_node['package'],
                            component_version=item_node['installed'],
                            unique_id_from_tool=item_node['id'])
            items[finding.unique_id_from_tool] = finding

        return list(items.values())
