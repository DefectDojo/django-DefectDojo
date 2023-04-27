import json
from itertools import groupby
from itertools import islice
import logging
from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY = 'Info'


class GovulncheckParser:

    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    @staticmethod
    def get_location(data, node):
        while data['Calls']['Functions'][str(node)]['CallSites'][0]['Parent'] != 1:
            node = data['Calls']['Functions'][str(node)]['CallSites'][0]['Parent']
        return [f"{x['Pos']['Filename']}:{x['Pos']['Line']}:{x['Pos']['Column']}" for x in
                data['Calls']['Functions'][str(node)]['CallSites']]

    @staticmethod
    def get_version(data, node):
        return data['Requires']['Modules'][str(node)]['Version']

    def get_findings(self, scan_file, test):
        findings = []
        try:
            data = json.load(scan_file)
        except Exception as e:
            raise ValueError("Invalid JSON format")
        else:
            if data['Vulns']:
                list_vulns = data['Vulns']
                for cve, elems in groupby(list_vulns, key=lambda vuln: vuln['OSV']['aliases'][0]):
                    first_elem = list(islice(elems, 1))
                    d = {
                        'cve': cve,
                        'severity': SEVERITY,
                        'title': first_elem[0]['OSV']['id'],
                        'component_name': first_elem[0]['OSV']['affected'][0]['package']['name'],
                        'component_version': self.get_version(data, first_elem[0]['RequireSink']),
                    }
                    d['references'] = first_elem[0]['OSV']['references'][0]['url']
                    d['url'] = first_elem[0]['OSV']['affected'][0]['database_specific']['url']
                    d['unique_id_from_tool'] = first_elem[0]['OSV']['id']
                    vuln_methods = set(
                        first_elem[0]['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])
                    impact = set(self.get_location(data, first_elem[0]['CallSink']))
                    for elem in elems:
                        impact.update(self.get_location(data, elem['CallSink']))
                        vuln_methods.update(
                            elem['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])
                    d['impact'] = '; '.join(impact) if impact else None
                    d['description'] = f"Vulnerable functions: {'; '.join(vuln_methods)}"
                    findings.append(Finding(**d))
            return findings
