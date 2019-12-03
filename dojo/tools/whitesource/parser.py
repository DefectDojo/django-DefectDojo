import hashlib
import json
from dojo.models import Finding

__author__ = 'dr3dd589'


class WhitesourceJSONParser(object):
    def __init__(self, file, test):
        self.dupes = dict()
        self.items = ()
        dupe_key = None

        if file is None:
            return

        data = file.read()
        try:
            content = json.loads(str(data, 'utf-8'))
        except:
            content = json.loads(data)

        def _build_common_output(node, lib_name=None):
            # project only available in manual export
            # name --> CVE in manual, library name in pipeline
            project = ""
            cve = None
            if 'library' in node:
                project = node.get('project')
                description = "**Description** : " + node.get('description', "") + "\n\n" + \
                            "**Library Name** : " + node['library'].get('name', "") + "\n\n" + \
                            "**Library Filename** : " + node['library'].get('filename', "") + "\n\n" + \
                            "**Library Description** : " + node['library'].get('description', "") + "\n\n" + \
                            "**Library Type** : " + node['library'].get('type', "") + "\n"
                lib_name = node['library'].get('filename')
            else:
                description = node.get('description')

            cve = node.get('name')
            title = cve + " | " + lib_name
            severity = node.get('severity').lower().capitalize()
            cvss3_score = node.get('cvss3_score')

            try:
                mitigation = "**fixResolution** : " + node['topFix']['fixResolution'] + "\n" + \
                            "**Message** : " + node['topFix']['message'] + "\n"
            except:
                mitigation = "N/A"

            # TODO, if file generated in a build pipeline, sourceFiles will likely be available to augment the file_path info
            
            return { 'title': title, 
                     'description': description,
                     'severity': severity,
                     'mitigation': mitigation,
                     'cve': cve,
                     'cvss3_score': cvss3_score
            }

        def _dedup_and_create_finding(vuln):
            dupe_key = hashlib.md5(vuln.get('description').encode('utf-8') + vuln.get('title').encode('utf-8')).hexdigest()

            if dupe_key in self.dupes:
                finding = self.dupes[dupe_key]
                if finding.description:
                    finding.description = finding.description
                self.dupes[dupe_key] = finding
            else:
                self.dupes[dupe_key] = True

                finding = Finding(title=vuln.get('title'),
                                test=test,
                                description=vuln.get('description'),
                                severity=vuln.get('severity'),
                                cve=vuln.get('cve'),
                                mitigation=vuln.get('mitigation'),
                                numerical_severity=Finding.get_numerical_severity(
                                    vuln.get('severity')),
                                dynamic_finding=True)
                
                self.dupes[dupe_key] = finding
        
        output = []
        if "libraries" in content:
            # we are likely dealing with a report generated from CLI with -generateScanReport,
            # which will output vulnerabilities as an array of a library
            # In this scenario, build up a an array
            tree_libs = content.get('libraries')
            # output = []
            for lib_node in tree_libs:
                # get the overall lib info here, before going into vulns
                if 'vulnerabilities' in lib_node and len(lib_node.get('vulnerabilities')) > 0:
                    for vuln in lib_node.get('vulnerabilities'):
                        output.append(_build_common_output(vuln, lib_node.get('name')))

        elif "vulnerabilities" in content:
            # likely a manual json export for vulnerabilities only for a project.
            # Vulns are standalone, and library is a property.
            tree_node = content['vulnerabilities']
            for node in tree_node:
                output.append(_build_common_output(node))

        #if(isinstance(output, list)):
            # dealing with possible multiple findings
        for vuln in output:
            _dedup_and_create_finding(vuln)
        #else:
            # or just one finding
            #_dedup_and_create_finding(output)

        # returns
        self.items = self.dupes.values()
