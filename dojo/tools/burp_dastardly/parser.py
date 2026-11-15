import logging

from defusedxml import ElementTree

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

    # Dastardly emits un-namespaced, JUnit-style XML whose root is
    # <testsuites>; get_items reads the <testsuite> children of that root.
    # Anything else is rejected rather than imported as an empty scan. That
    # includes a standalone <testsuite> root, which get_items cannot read back
    # as findings because it only looks below the root, and namespaced roots,
    # because the child lookup is un-namespaced.
    ALLOWED_ROOTS = {"testsuites"}
    READ_ELEMENTS = {"testsuite", "testcase", "failure"}

    def get_findings(self, xml_output, test):
        tree = ElementTree.parse(xml_output, ElementTree.XMLParser())
        root = tree.getroot()
        if root.tag not in self.ALLOWED_ROOTS:
            msg = (
                f"Unexpected root element '{root.tag}' in Burp Dastardly "
                f"report; expected an un-namespaced 'testsuites' root. "
                f"Refusing to treat an out-of-contract document as an "
                f"empty scan."
            )
            logger.warning(msg)
            raise ValueError(msg)
        for node in root.iter():
            if node.tag.startswith("{") and node.tag.split("}", 1)[-1] in self.READ_ELEMENTS:
                msg = (
                    f"Namespaced element '{node.tag}' in Burp Dastardly "
                    f"report; the parser only reads un-namespaced testsuite, "
                    f"testcase and failure elements. Refusing to import a "
                    f"report that would produce no findings."
                )
                logger.warning(msg)
                raise ValueError(msg)
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
