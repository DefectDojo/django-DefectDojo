import json

from dojo.models import Finding


class GoVulnCheckParser:

    def get_scan_types(self):
        return "GoVulnCheck Scanner"

    def get_label_for_scan_types(self, scan_type):
        return "GoVulnCheck scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import GoVulnCheck Scanner findings in JSON format."

    def getVulns(self, data):
        findings = []
        ignore = []
        for vuln in data['Vulns']:
            if vuln['OSV']['aliases'] in ignore:
                continue
            references = []
            endpoints = []
            node = vuln['CallSink']
            call = data['Calls']['Functions'][str(node)]
            location = call['CallSites'][0]['Pos']['Filename'] + ':' + str(call['CallSites'][0]['Pos']['Line']) + ':' \
                       + str(call['CallSites'][0]['Pos']['Column'])
            descrip_vuln = vuln['OSV']
            title = descrip_vuln['id']
            date = descrip_vuln['published']
            cve = descrip_vuln['aliases']
            ignore.append(cve)
            description = descrip_vuln['details']
            url = descrip_vuln['affected'][0]['database_specific']['url']
            impact = descrip_vuln['affected'][0]['ecosystem_specific']['imports'][0]['symbols']
            endpoints.append(location)
            for i in descrip_vuln['references']:
                references.append(i['url'])

            for vuln2 in data['Vulns']:
                if vuln2['OSV']['aliases'] == cve:
                    node2 = vuln2['CallSink']
                    call = data['Calls']['Functions'][str(node2)]
                    location2 = call['CallSites'][0]['Pos']['Filename'] + ':' + str(
                        call['CallSites'][0]['Pos']['Line']) + ':' \
                                + str(call['CallSites'][0]['Pos']['Column'])
                    endpoints.append(location2)

            finding = Finding(
                title=title,
                cve=cve,
                references=references,
                description=description,
                url=url,
                date=date,
                impact=impact,
                endpoints=endpoints
            )
            findings.append(finding)
        return findings

    def get_findings(self, scan_file, test):
        scan_data = scan_file.read()
        data = json.loads(scan_data)
        return self.getVulns(data)
