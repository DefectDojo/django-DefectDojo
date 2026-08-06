import io

from dojo.models import Finding, Test
from dojo.tools.stig_checklist.parser import StigChecklistParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path

# One CKL VULN with a status STIG Viewer never writes, and one with no V-number at all.
MALFORMED_CKL = """<?xml version="1.0" encoding="UTF-8"?>
<CHECKLIST>
  <ASSET><HOST_NAME>h1</HOST_NAME></ASSET>
  <STIGS><iSTIG><STIG_INFO/>
    <VULN>
      <STIG_DATA><VULN_ATTRIBUTE>Vuln_Num</VULN_ATTRIBUTE><ATTRIBUTE_DATA>V-1</ATTRIBUTE_DATA></STIG_DATA>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>Rule one</ATTRIBUTE_DATA></STIG_DATA>
      <STATUS>Something_Else</STATUS>
    </VULN>
    <VULN>
      <STIG_DATA><VULN_ATTRIBUTE>Rule_Title</VULN_ATTRIBUTE><ATTRIBUTE_DATA>No V number</ATTRIBUTE_DATA></STIG_DATA>
      <STATUS>Open</STATUS>
    </VULN>
  </iSTIG></STIGS>
</CHECKLIST>"""


class TestStigChecklistParser(DojoTestCase):
    def parse(self, filename, mode="r"):
        path = get_unit_tests_scans_path("stig_checklist") / filename
        # Real uploads arrive as binary handles; the text mode here matches how the other parser
        # tests open their samples. Both are exercised: windows1252.ckl is opened as bytes.
        kwargs = {"encoding": "utf-8"} if mode == "r" else {}
        with path.open(mode, **kwargs) as file:
            findings = StigChecklistParser().get_findings(file, Test())
        self.validate_locations(findings)
        return findings

    def status_flags(self, finding):
        return (finding.active, finding.verified, finding.is_mitigated, finding.out_of_scope)

    def hosts(self, finding):
        return [location.host for location in self.get_unsaved_locations(finding)]

    def by_vuln_num(self, findings):
        return {finding.vuln_id_from_tool: finding for finding in findings}

    def test_scan_type_metadata(self):
        parser = StigChecklistParser()
        self.assertEqual(["DISA STIG Checklist"], parser.get_scan_types())
        self.assertEqual("DISA STIG Checklist", parser.get_label_for_scan_types("DISA STIG Checklist"))
        self.assertIn(".cklb", parser.get_description_for_scan_types("DISA STIG Checklist"))

    def test_ckl_mixed_statuses_flags(self):
        """
        Every checklist status maps to a distinct set of finding flags.

        NotAFinding and Not_Applicable carry is_mitigated/out_of_scope rather than only
        active=False, because on reimport a merely inactive incoming finding is a no-op.
        """
        findings = self.by_vuln_num(self.parse("rhel9_mixed_statuses.ckl"))
        self.assertEqual(4, len(findings))
        # Open
        self.assertEqual((True, True, False, False), self.status_flags(findings["V-257777"]))
        # NotAFinding
        self.assertEqual((False, False, True, False), self.status_flags(findings["V-257778"]))
        # Not_Applicable
        self.assertEqual((False, False, False, True), self.status_flags(findings["V-257779"]))
        # Not_Reviewed
        self.assertEqual((True, False, False, False), self.status_flags(findings["V-257781"]))
        for finding in findings.values():
            self.assertFalse(finding.false_p)

    def test_ckl_field_mapping(self):
        """Full field mapping of an Open item, from a STIG Viewer 2.x export."""
        finding = self.by_vuln_num(self.parse("rhel9_mixed_statuses.ckl"))["V-257777"]

        self.assertEqual("V-257777 - RHEL 9 must be a vendor-supported release.", finding.title)
        self.assertEqual("High", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("CAT I", finding.impact)
        self.assertEqual("V-257777", finding.vuln_id_from_tool)
        self.assertEqual("rhel9.example.mil/V-257777", finding.unique_id_from_tool)
        self.assertEqual("RHEL_9_STIG", finding.component_name)
        self.assertEqual("V2R3", finding.component_version)
        self.assertEqual(["stig"], finding.unsaved_tags)
        self.assertTrue(finding.dynamic_finding)
        self.assertFalse(finding.static_finding)
        self.assertIsNone(finding.severity_justification)

        self.assertEqual("Upgrade to a supported version of RHEL 9.", finding.mitigation)
        self.assertIn("cat /etc/redhat-release", finding.steps_to_reproduce)

        self.assertIn("**Rule Version (STIG-ID):** RHEL-09-211010", finding.description)
        # The revision-suffixed Rule_ID is recorded for the reader but never used as identity.
        self.assertIn("**Rule ID:** SV-257777r925318_rule", finding.description)
        self.assertIn("continues to provide security patches", finding.description)
        self.assertIn("**Finding Details:** Installed release reached end of maintenance", finding.description)
        self.assertIn("**Comments:** Upgrade scheduled", finding.description)

        # The FQDN wins over the host name and the IP the checklist also recorded.
        self.assertEqual(["rhel9.example.mil"], self.hosts(finding))

    def test_ckl_references_carry_every_cci_once(self):
        """
        The bare CCI lines are a contract: Pro reads them back to map items onto NIST controls.

        A CKL repeats a CCI_REF block per reference, and this sample repeats CCI-000366, so the
        order-preserving dedupe is what keeps one line per CCI.
        """
        finding = self.by_vuln_num(self.parse("rhel9_mixed_statuses.ckl"))["V-257777"]
        lines = finding.references.splitlines()

        self.assertIn("**STIG:** Red Hat Enterprise Linux 9 Security Technical Implementation Guide "
                      ":: Version 2, Release: 3 Benchmark Date: 24 Jul 2024", lines)
        self.assertIn("**Rule:** SV-257777r925318_rule (RHEL-09-211010)", lines)
        self.assertEqual(["CCI-000366", "CCI-002617"], [line for line in lines if line.startswith("CCI-")])

    def test_ckl_severity_override(self):
        """An assessor severity override moves the severity but not the rule's DISA category."""
        finding = self.by_vuln_num(self.parse("rhel9_mixed_statuses.ckl"))["V-257781"]
        self.assertEqual("Low", finding.severity)
        self.assertEqual("CAT II", finding.impact)
        self.assertIn("overridden from 'medium' to 'low'", finding.severity_justification)
        self.assertIn("isolated management enclave", finding.severity_justification)

    def test_cklb_mixed_statuses_flags(self):
        """The same four statuses, expressed in STIG Viewer 3.x's snake_case JSON."""
        findings = self.by_vuln_num(self.parse("rhel9_mixed_statuses.cklb"))
        self.assertEqual(4, len(findings))
        self.assertEqual((True, True, False, False), self.status_flags(findings["V-257777"]))
        self.assertEqual((False, False, True, False), self.status_flags(findings["V-257778"]))
        self.assertEqual((False, False, False, True), self.status_flags(findings["V-257779"]))
        self.assertEqual((True, False, False, False), self.status_flags(findings["V-257781"]))
        self.assertEqual("Low", findings["V-257781"].severity)
        self.assertIn("isolated management enclave", findings["V-257781"].severity_justification)

    def test_ckl_and_cklb_agree(self):
        """
        The two formats describe the same assessment, so they must produce the same findings.

        This is what stops the XML and JSON readers drifting apart: a change to one that is not
        mirrored in the other fails here.
        """
        def identity(finding):
            return (
                finding.title, finding.severity, finding.impact,
                finding.active, finding.verified, finding.is_mitigated, finding.out_of_scope,
                finding.vuln_id_from_tool, finding.unique_id_from_tool,
                finding.component_name, finding.component_version,
                finding.references, finding.mitigation, finding.steps_to_reproduce,
            )

        ckl = self.parse("rhel9_mixed_statuses.ckl")
        cklb = self.parse("rhel9_mixed_statuses.cklb")
        self.assertEqual(sorted(map(identity, ckl)), sorted(map(identity, cklb)))

    def test_multiple_istig_blocks(self):
        """One host assessed against two STIGs: both benchmarks' items are imported."""
        findings = self.by_vuln_num(self.parse("multi_istig.ckl"))
        self.assertEqual(2, len(findings))
        self.assertEqual("RHEL_9_STIG", findings["V-257777"].component_name)
        self.assertEqual("V2R3", findings["V-257777"].component_version)
        self.assertEqual("APACHE_2-4_UNIX_SERVER_STIG", findings["V-214244"].component_name)
        self.assertEqual("V3R1", findings["V-214244"].component_version)
        for vuln_num, finding in findings.items():
            self.assertEqual(f"webhost.example.mil/{vuln_num}", finding.unique_id_from_tool)
            self.assertEqual(["webhost.example.mil"], self.hosts(finding))

    def test_blank_host(self):
        """An un-keyed checklist has no host to report, so the V-number stands alone as the id."""
        findings = self.parse("blank_host.ckl")
        self.assertEqual(1, len(findings))
        self.assertEqual("V-257777", findings[0].unique_id_from_tool)
        self.assertEqual([], self.hosts(findings[0]))

    def test_no_vulns(self):
        """A checklist opened but never assessed carries STIG_INFO and no VULN elements."""
        self.assertEqual(0, len(self.parse("no_vulns.ckl")))

    def test_windows_1252_encoded_ckl(self):
        """
        STIG Viewer exports are not always UTF-8.

        This sample declares windows-1252 in its prolog and contains bytes that are not valid
        UTF-8, so it only parses because the XML is handed to the parser as bytes.
        """
        findings = self.parse("windows1252.ckl", mode="rb")
        self.assertEqual(1, len(findings))
        # Escaped rather than literal: these are the two cp1252 bytes (0x92, 0x97) the sample
        # carries, and spelling them out keeps it obvious which characters are under test.
        self.assertIn("vendor\u2019s maintenance support window", findings[0].description)
        self.assertIn("\u2014 published per release \u2014", findings[0].description)

    def test_cklb_with_utf8_bom(self):
        """A BOM ahead of the JSON must not defeat format detection."""
        findings = self.parse("bom.cklb")
        self.assertEqual(1, len(findings))
        self.assertEqual("bomhost.example.mil/V-257777", findings[0].unique_id_from_tool)

    def test_cklb_missing_keys(self):
        """Checklist writers other than STIG Viewer omit keys; none of them are required."""
        findings = self.by_vuln_num(self.parse("cklb_missing_keys.cklb"))
        self.assertEqual(2, len(findings))
        # No severity recorded: imported as Info rather than dropped, with no DISA category.
        self.assertEqual("Info", findings["V-257777"].severity)
        self.assertIsNone(findings["V-257777"].impact)
        self.assertIsNone(findings["V-257777"].component_version)
        # host_name is the only identifier this checklist recorded.
        self.assertEqual(["sparsehost"], self.hosts(findings["V-257777"]))
        self.assertEqual("sparsehost/V-257778", findings["V-257778"].unique_id_from_tool)

    def test_unknown_status_and_missing_vuln_num(self):
        """An unrecognised status defaults to Not_Reviewed; an item with no V-number has no identity."""
        findings = StigChecklistParser().get_findings(io.StringIO(MALFORMED_CKL), Test())
        self.assertEqual(1, len(findings))
        self.assertEqual("h1/V-1", findings[0].unique_id_from_tool)
        self.assertEqual((True, False, False, False), self.status_flags(findings[0]))

    def test_files_that_are_not_checklists_are_rejected(self):
        """
        Every rejection is a ValueError, which the importer turns into a clean validation error.

        A defusedxml ParseError escaping the parser would surface as a server error instead.
        """
        cases = {
            "plain text": io.StringIO("hello"),
            "xccdf benchmark": io.StringIO('<Benchmark xmlns="http://checklists.nist.gov/xccdf/1.2"/>'),
            "truncated xml": io.StringIO("<CHECKLIST><ASSET>"),
            "json array": io.StringIO("[1, 2]"),
            "broken json": io.StringIO('{"stigs": ['),
        }
        for label, handle in cases.items():
            with self.subTest(case=label), self.assertRaises(ValueError):
                StigChecklistParser().get_findings(handle, Test())

    def test_xccdf_rejection_names_the_right_parser(self):
        """XCCDF benchmark results are a different tool; say so rather than failing opaquely."""
        with self.assertRaises(ValueError) as context:
            StigChecklistParser().get_findings(io.StringIO("<Benchmark/>"), Test())
        self.assertIn("Openscap", str(context.exception))
