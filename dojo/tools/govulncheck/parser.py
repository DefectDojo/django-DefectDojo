import json

from dojo.models import Finding


class govulncheckParser:

    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    def get_findings(self, scan_file, test):

        # get data from report.json
        scan_data = scan_file.read()
        # remove into from developer
        pos_json = scan_data.find(b'{')
        scan_data = scan_data[pos_json:]
        data = json.loads(scan_data)

        # init lists
        findings = []
        ignore = []

        # cycle for every object from block Vulns
        for vuln in data['Vulns']:
            if vuln['OSV']['aliases'] in ignore:
                continue

            # get info from field
            refs = []
            vuln_files = []
            node = vuln['CallSink']
            call = data['Calls']['Functions'][str(node)]
            location = call['CallSites'][0]['Pos']['Filename'] + ':' + str(call['CallSites'][0]['Pos']['Line']) + ':' \
                       + str(call['CallSites'][0]['Pos']['Column'])
            descrip_vuln = vuln['OSV']
            title = descrip_vuln['id']
            date = descrip_vuln['published']
            date = date[0:10]
            cve = descrip_vuln['aliases'][0]
            ignore.append(cve)
            description = descrip_vuln['details']
            url = descrip_vuln['affected'][0]['database_specific']['url']
            impact = descrip_vuln['affected'][0]['ecosystem_specific']['imports'][0]['symbols']

            vuln_files.append(location)
            for i in descrip_vuln['references']:
                refs.append(i['url'])

            # find vuln with same CVE and collecting additional information
            for similar_vuln in data['Vulns']:
                if similar_vuln['OSV']['aliases'][0] == cve:
                    similar_node = similar_vuln['CallSink']
                    call = data['Calls']['Functions'][str(similar_node)]
                    new_location = call['CallSites'][0]['Pos']['Filename'] + ':' + str(
                        call['CallSites'][0]['Pos']['Line']) + ':' \
                                   + str(call['CallSites'][0]['Pos']['Column'])
                    vuln_files.append(new_location)

            # prepare info
            references = '\n'.join(str(i) for i in refs)
            impact = 'Vulnerable method: ' + ", ".join(str(i) for i in impact)
            impact = impact + "\nVulnerable endpoints: \n" + '\n'.join(str(i) for i in vuln_files)
            severity = 'Info'

            # create Finding
            finding = Finding(
                title=title,
                cve=cve,
                references=references,
                description=description,
                url=url,
                impact=impact,
                severity=severity,
            )
            # Finding put in list
            findings.append(finding)

        return findings
