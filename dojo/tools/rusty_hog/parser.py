import json
from dojo.tools.parser_test import ParserTest
from dojo.models import Finding


class RustyhogParser(object):

    def get_scan_types(self):
        return ["Rusty Hog Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Rusty Hog Scan - JSON Report"

    def get_findings(self, json_output, test):
        tree = json.load(json_output)
        return self.get_items(tree, test)

    def parse_json(self, json_output):
        try:
            data = json_output.read()
            try:
                tree = json.loads(str(data, 'utf-8'))
            except:
                tree = json.loads(data)
        except:
            raise Exception("Invalid format")
        return tree

    def get_items(self, tree, test):
        items = {}
        for node in tree:
            item = self.get_item(node, test)
            unique_key = "Finding {}".format(tree.index(node))
            items[unique_key] = item
        return list(items.values())

    def get_tests(self, scan_type, handle):
            tree = json.load(handle)
            tests = list()
            parsername = "Rusty Hog"
            for node in tree:
                if 'commit' in node or 'commitHash' in node or 'parent_commit_hash' in node or 'old_file_id' in node or 'new_file_id' in node:
                    parsername = "Choctaw Hog"
                    break
                if 'issue_id' in node or 'location' in node or 'url' in node:
                    parsername = "Gottingen Hog"
                    break
            #for run in tree.get('runs', list()):
            test = ParserTest(
                name=parsername,
                type=parsername,
                version="",
            )
            if parsername == "Rusty Hog":
                test.description = "The exact scanner within Rusty Hog could not be determined due to missing information within the scan result."
            else:
                test.description = parsername
            test.findings = self.__getitem(vulnerabilities=tree, scanner=parsername)
            tests.append(test)
            return tests

    def __getitem(self, vulnerabilities, scanner):
        findings = []
        line = ""
        cwe = 200
        for vulnerability in vulnerabilities:
            if scanner == "Rusty Hog":
                break
            elif scanner == "Choctaw Hog":
                """Choctaw Hog"""
                description = "**This string was found:** {}".format(vulnerability.get('stringsFound'))
                if vulnerability.get('commit') is not None:
                    description += "\n**Commit message:** {}".format(vulnerability.get('commit'))
                if vulnerability.get('commitHash') is not None:
                    description += "\n**Commit hash:** {}".format(vulnerability.get('commitHash'))
                if vulnerability.get('parent_commit_hash') is not None:
                    description += "\n**Parent commit hash:** {}".format(vulnerability.get('parent_commit_hash'))
                if vulnerability.get('old_file_id') is not None and vulnerability.get('new_file_id') is not None:
                    description += "\n**Old and new file IDs:** {} - {}".format(
                                    vulnerability.get('old_file_id'),
                                    vulnerability.get('new_file_id'))
                if vulnerability.get('old_line_num') is not None and vulnerability.get('new_line_num') is not None:
                    description += "\n**Old and new line numbers:** {} - {}".format(
                                    vulnerability.get('old_line_num'),
                                    vulnerability.get('new_line_num'))
            elif scanner == "Gottingen Hog":
                """Gottingen Hog"""
                description = "**This string was found:** {}".format(vulnerability.get('stringsFound'))
                if vulnerability.get('issue_id') is not None:
                    description += "\n**JIRA Issue ID:** {}".format(vulnerability.get('issue_id'))
                if vulnerability.get('location') is not None:
                    description += "\n**JIRA location:** {}".format(vulnerability.get('location'))
                if vulnerability.get('url') is not None:
                    description += "\n**JIRA url:** {}".format(vulnerability.get('url'))
            """General - for all Rusty Hogs"""
            file_path = vulnerability.get('path')
            if vulnerability.get('date') is not None:
                description += "\n**Date:** {}".format(vulnerability.get('date'))
            """Finding Title"""
            if scanner == "Choctaw Hog":
                title = "{} found in Git path {} ({})".format(
                        vulnerability.get('reason'),
                        vulnerability.get('path'),
                        vulnerability.get('commitHash'))
            elif scanner == "Gottingen Hog":
                title = "{} found in Jira ID {}".format(
                        vulnerability.get('reason'),
                        vulnerability.get('issue_id'),
                        vulnerability.get('location'))
            # create the finding object
            finding = Finding(
                title=title,
                #test=test,
                severity='High',
                cwe=cwe,
                description=description,
                mitigation="Please ensure no secret material nor confidential information is kept in clear within git repositories.",
                file_path=file_path,
                static_finding=True,
                dynamic_finding=False
            )
            finding.description = finding.description.strip()
            findings.append(finding)
        return findings
