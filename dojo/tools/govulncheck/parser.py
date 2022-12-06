import json
from itertools import groupby
from itertools import islice
from dojo.models import Finding

SEVERITY = 'Info'
NO_IMPACT = "In your code no call of these vulnerable function, but they in call stack of other function"


class GovulncheckParser:

    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    @staticmethod
    def get_location(data, node):
        return [f"{x['Pos']['Filename']}:{x['Pos']['Line']}:{x['Pos']['Column']}" for x in
                data['Calls']['Functions'][str(node)]['CallSites'] if x['Parent'] == 1]

    def get_findings(self, scan_file, test):
        findings = []
        scan_data = scan_file.read()
        # remove intro from developer
        scan_data = scan_data[scan_data.find(b'{'):]
        try:
            data = json.loads(scan_data)
        except Exception:
            return findings
        else:
            list_vulns = data['Vulns']

            for cve, elems in groupby(list_vulns, key=lambda vuln: vuln['OSV']['aliases'][0]):
                d = dict()
                first_elem = list(islice(elems, 1))
                d['cve'] = cve
                d['severity'] = SEVERITY
                d['title'] = first_elem[0]['OSV']['id']
                d['component_name'] = first_elem[0]['OSV']['affected'][0]['package']['name']
                d['references'] = first_elem[0]['OSV']['references'][0]['url']
                d['url'] = first_elem[0]['OSV']['affected'][0]['database_specific']['url']
                vuln_methods = set(first_elem[0]['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])
                impact = set(self.get_location(data, first_elem[0]['CallSink']))
                for elem in elems:
                    impact.update(self.get_location(data, elem['CallSink']))
                    vuln_methods.update(elem['OSV']['affected'][0]['ecosystem_specific']['imports'][0]['symbols'])
                d['impact'] = '; '.join(impact) if impact else NO_IMPACT
                d['description'] = f"Vulnerable functions: {'; '.join(vuln_methods)}"
                findings.append(Finding(**d))
            return findings
