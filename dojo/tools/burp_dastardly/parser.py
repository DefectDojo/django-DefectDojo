import logging

from defusedxml import ElementTree as etree

from dojo.models import Finding

logger = logging.getLogger(__name__)


class BurpDastardlyParser:

    def get_scan_types(self):
        return ["Burp Dastardly Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Burp Dastardly Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import Burp Dastardly XML files."
        )

    def get_findings(self, xml_output, test):
        tree = etree.parse(xml_output, etree.XMLParser())
        return self.get_items(tree, test)

    def get_items(self, tree, test):
        items = []
        for node in tree.findall("testsuite"):
            if int(node.attrib["failures"]) != 0:
                name = node.attrib["name"]
                testcase = node.findall("testcase")
                for case in testcase:
                    for fail in case.findall("failure"):
                        title = fail.attrib["message"]
                        severity = fail.attrib["type"]
                        description = fail.text
                        finding = Finding(
                            title=title,
                            url=name,
                            test=test,
                            severity=severity,
                            description=description,
                            false_p=False,
                            duplicate=False,
                            out_of_scope=False,
                            mitigated=None,
                            dynamic_finding=True,
                        )
                        items.append(finding)
        return items
