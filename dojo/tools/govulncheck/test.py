import json

SCAN_FILE = "report.json"


def getPos(vuln):
    node = vuln['CallSink']
    call = data['Calls']['Functions'][str(node)]
    location = call['CallSites'][0]['Pos']['Filename'] + ':' + str(call['CallSites'][0]['Pos']['Line']) + ':'\
               + str(call['CallSites'][0]['Pos']['Column'])
    return location


def getVulns(data):
    findings = []
    #pprint (data['Vulns'])
    ignore = []
    for vuln in data['Vulns']:
        if vuln['OSV']['aliases'] in ignore:
            continue
        references = []
        endpoints = []
        location_of_use = getPos(vuln)
        descrip_vuln = vuln['OSV']
        title = descrip_vuln['id']
        date = descrip_vuln['published']
        cve = descrip_vuln['aliases']
        ignore.append(cve)
        description = descrip_vuln['details']
        url = descrip_vuln['affected'][0]['database_specific']['url']
        impact = descrip_vuln['affected'][0]['ecosystem_specific']['imports'][0]['symbols']
        endpoints.append(location_of_use)
        for i in descrip_vuln['references']:
            references.append(i['url'])

        for vuln2 in data['Vulns']:
            if vuln2['OSV']['aliases'] == cve:
                endpoints.append(getPos(vuln2))

        finding = Finding(
            title=title,
            cve=cve,
            references=references,
            description=description,
            url=url,
            date=date,
            impact=impact
        )
        findings.append(finding)
    return findings


with open(SCAN_FILE) as f:
    scan_data = f.read()
    data = json.loads(scan_data)
    print(getVulns(data))

