import json

from dojo.models import Finding
from dojo.tools.parser_test import ParserTest


class GitlabParser(object):

    scan_types = {
        "GitLab API Fuzzing Report Scan": ("api_fuzzing", "dynamic"),
        "GitLab Cluster Image Scanning Report": ("cluster_image_scanning", "static"),
        "GitLab Container Scan": ("container_scanning", "static"),
        "GitLab Coverage-Guided Fuzz Testing Report Scan": ("coverage_fuzzing", "static"),
        "GitLab DAST Report": ("dast", "dynamic"),
        "GitLab Dependency Scanning Report": ("dependency_scanning", "static"),
        "GitLab SAST Report": ("sast", "static"),
        "GitLab Secret Detection Report": ("secret_detection", "static"),
    }

    findings = {}

    def get_scan_types(self):
        return scan_types.keys()

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return f"Import {scan_type} vulnerabilities in JSON format."

    def get_tests(self, scan_type, json_output):

        if json_output is None:
            return

        tree = self.parse_json(json_output)

        if tree:
            self.scan_type = scan_type

            test = ParserTest(
                name=tree.get('scan', {}).get('scanner', {}).get('name'),
                type=tree.get('scan', {}).get('type'),
                version=tree.get('scan', {}).get('scanner', {}).get('version')
            )

            test.findings = self.get_items(tree)
            return [test]

    def get_findings(self, json_output, test):

        if json_output is None:
            return

        tree = self.parse_json(json_output)

        if tree:
            self.scan_type = test.scan_type
            return self.get_items(tree)

    def parse_json(self, json_output):
        data = json_output.read()
        try:
            tree = json.loads(str(data, 'utf-8'))
        except:
            tree = json.loads(data)

        return tree

    def get_items(self, tree):

        scan = tree.get('scan', {})

        for vuln in tree.get('vulnerabilities', []):
            finding = self.get_item(vuln, scan)
            if item:
                if finding.unique_id_from_tool in self.findings:
                    self.findings[finding.unique_id_from_tool].unsaved_endpoints.extend(finding.unsaved_endpoints)
                else:
                    self.findings[finding.unique_id_from_tool] = finding

        self.add_remediations(tree)

        return list(self.findings.values())

    def get_item(self, vuln, scan):

        requested_category, sast_or_dast = self.scan_types[self.scan_type]
        if requested_category != vuln.get('category'):
            # We are processing only if scan type which was defined in request is the same as it is in finding
            return None

        # ID
        unique_id_from_tool = None
        if 'id' in vuln:
            unique_id_from_tool = vuln['id']
        else:
            # If the new unique id is not provided, fall back to deprecated "cve" fingerprint (old version)
            unique_id_from_tool = vuln['cve']

        # TITLE
        title = ''
        if 'name' in vuln:
            title = vuln['name']
        elif 'message' in vuln:
            title = vuln['message']
        elif 'description' in vuln:
            title = vuln['description']
        else:
            # All other fields are optional, if none of them has a value, fall back on the unique id
            title = unique_id_from_tool

        # DESCRIPTION
        description = 'Scanner: {}\n'.format(vuln['scanner']['name'])
        if 'message' in vuln:
            description += '{}\n'.format(vuln['message'])
        if 'description' in vuln:
            description += '{}\n'.format(vuln['description'])

        # SEVERITY
        severity = vuln.get('severity')
        if severity is None or severity == 'Undefined' or severity == 'Unknown':
            severity = 'Info'

        # CONFIDENCE
        scanner_confidence = self.get_confidence_numeric(vuln.get('confidence', 'Unkown'))

        # MITIGATION
        mitigation = vuln.get('solution')

        # CVE, CWE, REFERECIES
        cwe = None
        cve = None
        references = ''
        if 'identifiers' in vuln:
            for identifier in vuln['identifiers']:
                if identifier['type'].lower() == 'cwe':
                    if isinstance(identifier['value'], int):
                        cwe = identifier['value']
                    elif identifier['value'].isdigit():
                        cwe = int(identifier['value'])
                elif identifier['type'].lower() == 'cve':
                    cve = identifier['value']
                else:
                    references += 'Identifier type: {}\n'.format(identifier['type'])
                    references += 'Name: {}\n'.format(identifier['name'])
                    references += 'Value: {}\n'.format(identifier['value'])
                    if 'url' in identifier:
                        references += 'URL: {}\n'.format(identifier['url'])
                    references += '\n'
        if 'links' in vuln:
            for link in vuln["links"]:
                references += "URL: {}\n".format(link['url'])
        if references == '':
            references = None

        # DESCRIPTION - Source code
        # We do not show source code if it can leak secret
        if 'raw_source_code_extract' in vuln and requested_category != 'secret_detection':
            description += 'Source code: {}\n'.format(vuln['raw_source_code_extract'])

        # DATE
        date = None
        if "discovered_at" in vuln:
            date = datetime.strptime(vuln["discovered_at"], "%Y-%m-%dT%H:%M:%S.%f")
        elif "end_time" in scan:
            date = datetime.strptime(scan["end_time"], "%Y-%m-%dT%H:%M:%S.%f")

        # location
        loc = vuln.get("location", {})

        # FILE_PATH/SAST_FILE_PATH
        file_path = loc.get("file")

        # commit - not used

        # dependency
        dependency = loc.get("dependency", {})
        component_name = dependency.get("package", {}).get("name")
        component_version = dependency.get("version")
        # dependency[iid, direct, dependency_path] - not used

        # operating_system - not used

        # image
        if "image" in loc:
            description += "Image: {}\n".foramt(loc['image'])

        # default_branch_image
        if "default_branch_image" in loc:
            description += "Default branch image: {}\n".format(loc['default_branch_image'])

        # kubernetes_resource
        if "kubernetes_resource" in loc:
            description += "Kubernetes resource: {}\n".format(loc['kubernetes_resource'])

        # LINE/SAST_SOURCE_LINE
        line = None
        if "start_line" in loc:
            line = int(loc["start_line"])
        elif "end_line" in loc:
            line = int(loc["end_line"])

        # SAST_SOURCE_OBJECT/SAST_SINK_OBJECT
        sast_object = None
        if 'class' in loc and 'method' in loc:
            sast_object = '{}#{}'.format(loc['class'], loc['method'])
        elif 'class' in loc:
            sast_object = loc['class']
        elif 'method' in loc and sast_or_dast == 'static':  # Method can be also HTTP method in DAST
            sast_object = loc['method']

        # ENDPOINT
        endpoint = None
        if "hostname" in loc:
            endpoint = Endpoint.from_uri(host=loc['hostname'])
            if "path" in loc:
                endpoint.path = loc['path']

        # crash_address - TODO: missing in data -> unittest missing
        if "crash_address" in loc:
            description += "Crash address: {}\n".format(loc['crash_address'])

        # stacktrace_snippet
        if "stacktrace_snippet" in loc:
            description += "Stacktrace snippet: {}\n\n".format(loc['stacktrace_snippet'])

        # crash_state
        if "crash_state" in loc:
            description += "Crash state: {}\n\n".format(loc['crash_state'])

        # crash_type
        if "crash_type" in loc:
            description += "Crash type: {}\n\n".format(loc['crash_type'])

        finding = Finding(unique_id_from_tool=unique_id_from_tool,
                          title=title,
                          description=description,
                          severity=severity,
                          scanner_confidence=scanner_confidence,
                          mitigation=mitigation,
                          references=references,
                          cwe=cwe,
                          cve=cve,
                          date=date,
                          file_path=file_path,
                          component_name=component_name,
                          component_version=component_version,
                          line=line,
                          sast_source_object=sast_object,
                          sast_sink_object=sast_object,
                          sast_source_file_path=file_path,
                          sast_source_line=line,
                          static_finding=sast_or_dast == 'static',
                          dynamic_finding=sast_or_dast == 'dynamic'
                          )

        if endpoint:
            finding.unsaved_endpoints = [endpoint]

        # TODO: documented fields but never used in examples:
        # vuln['details']
        # vuln['tracking']
        # vuln['flags']
        # vuln['evidence']
        # vuln['assets']

        return finding

    def get_confidence_numeric(self, argument):
        switcher = {
            'Confirmed': 1,    # Certain
            'High': 3,         # Firm
            'Medium': 4,       # Firm
            'Low': 6,          # Tentative
            'Experimental': 7,  # Tentative
            'Unknown': 8,  # Tentative
            'Ignore': 10,  # Tentative
        }
        return switcher.get(argument)

    def add_remediations(self, tree):

        for remediation in tree.get('remediations', []):
            for rem_find in remediation.get('fixes', []):

                rem_find_id = rem_find.get('id') or rem_find.get('cve')  # one of them can be defined
                if rem_find_id in self.findings and "summary" in remediation:
                    # We are exctending 'mitigation' only if there is some 'summery'
                    # If there is already some 'mitigation', we are adding 'summery' after 2 new lines
                    mitigation = self.findings[rem_find_id].mitigation
                    mitigation = f"{mitigation}\n\n" if mitigation else ''
                    mitigation += remediation["summary"]
                    self.findings[rem_find_id].mitigation = mitigation
