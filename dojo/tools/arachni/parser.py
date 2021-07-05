import json
from datetime import datetime

import html2text
from django.utils.encoding import force_str

from dojo.models import Endpoint, Finding


class ArachniParser(object):
    """Arachni Web Scanner (http://arachni-scanner.com/wiki)

    Reports are generated with arachni_reporter tool:
    `./arachni_reporter --reporter 'json' js.com.afr`
    """

    def get_scan_types(self):
        return ["Arachni Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Arachni Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Arachni JSON report format (generated with `arachni_reporter --reporter 'json'`)."

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = {}
        report_date = None
        if 'finish_datetime' in tree:
            report_date = datetime.strptime(tree.get('finish_datetime'), '%Y-%m-%d %H:%M:%S %z')
        for node in tree['issues']:
            item = self.get_item(node, report_date)
            dupe_key = item.severity + item.title
            if dupe_key in items:
                items[dupe_key].unsaved_endpoints = items[dupe_key].unsaved_endpoints + item.unsaved_endpoints
                items[dupe_key].unsaved_req_resp = items[dupe_key].unsaved_req_resp + item.unsaved_req_resp
                items[dupe_key].nb_occurences += 1
            else:
                items[dupe_key] = item
                items[dupe_key].nb_occurences = 1

        return list(items.values())

    def get_item(self, item_node, report_date):
        # url management
        if 'vector' in item_node and 'action' in item_node['vector']:
            url = item_node['vector']['action']
        else:
            url = item_node['response']['url']

        request = item_node['request']
        #
        req = ''
        #
        for key, value in request.items():
            req += str(key) + ": " + str(value) + "\n\n"
        #
        respz = item_node['response']

        resp = ''

        for key, value in respz.items():
            if key != 'body':
                resp += str(key) + ": " + str(value) + "\n\n"

        resp += "\n\n\n" + force_str(respz['body'])
        unsaved_req_resp = list()

        if request is not None and respz is not None:
            unsaved_req_resp.append({"req": req, "resp": resp})

        endpoint = Endpoint.from_uri(url)

        description = item_node.get('description', 'N/A')
        description = html2text.html2text(description)

        remediation = item_node['remedy_guidance'] if 'remedy_guidance' in item_node else 'n/a'
        if remediation:
            remediation = html2text.html2text(remediation)

        references = list(item_node['references'].values()) if 'references' in item_node else None
        references = '<br/><br/>'.join(reference for reference in references)

        if references:
            references = html2text.html2text(references)

        severity = item_node.get('severity', 'Info').capitalize()
        if 'Informational' == severity:
            severity = 'Info'

        # Finding and Endpoint objects returned have not been saved to the database
        finding = Finding(title=item_node['name'],
                            date=report_date,
                            severity=severity,
                            description=description,
                            mitigation=remediation,
                            references=references,
                            impact="No impact provided",
                            cwe=item_node.get('cwe'),
                            vuln_id_from_tool=item_node.get('digest'),
                          )
        finding.unsaved_endpoints = [endpoint]
        finding.unsaved_req_resp = unsaved_req_resp
        finding.unsaved_tags = item_node.get('tags')

        return finding
