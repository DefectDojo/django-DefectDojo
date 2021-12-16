import json

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
            item = get_item(node, test)
            unique_key = "Finding {}".format(tree.index(node))
            items[unique_key] = item

        return list(items.values())


def get_item(vulnerability, test):
    cwe = 200
    description = "**This string was found:** {}".format(vulnerability.get('stringsFound'))
    if vulnerability.get('commit') is not None:
        description += "\n**Commit message:** {}".format(vulnerability.get('commit'))
    if vulnerability.get('commitHash') is not None:
        description += "\n**Commit hash:** {}".format(vulnerability.get('commitHash'))
    if vulnerability.get('parent_commit_hash') is not None:
        description += "\n**Parent commit hash:** {}".format(vulnerability.get('parent_commit_hash'))
    if vulnerability.get('date') is not None:
        description += "\n**Date:** {}".format(vulnerability.get('date'))
    if vulnerability.get('old_file_id') is not None and vulnerability.get('new_file_id') is not None:
        description += "\n**Old and new file IDs:** {} - {}".format(
                        vulnerability.get('old_file_id'),
                        vulnerability.get('new_file_id'))
    if vulnerability.get('old_line_num') is not None and vulnerability.get('new_line_num') is not None:
        description += "\n**Old and new line numbers:** {} - {}".format(
                        vulnerability.get('old_line_num'),
                        vulnerability.get('new_line_num'))
    if vulnerability.get('issue_id') is not None:
        description += "\n**JIRA Issue ID:** {}".format(vulnerability.get('issue_id'))
    if vulnerability.get('location') is not None:
        description += "\n**JIRA location:** {}".format(vulnerability.get('location'))
    if vulnerability.get('url') is not None:
        description += "\n**JIRA url:** {}".format(vulnerability.get('url'))
    file_path = vulnerability.get('path')
    title = "{} found in {} ({})".format(
            vulnerability.get('reason'),
            vulnerability.get('path'),
            vulnerability.get('commitHash'))

    # create the finding object
    finding = Finding(
        title=title,
        test=test,
        severity='High',
        cwe=cwe,
        description=description,
        mitigation="Please ensure no secret material nor confidential information is kept in clear within git repositories.",
        file_path=file_path,
        static_finding=True,
        dynamic_finding=False
    )

    finding.description = finding.description.strip()

    return finding
