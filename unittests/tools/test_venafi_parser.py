import io
import json
from datetime import UTC, datetime, timedelta

from dojo.models import Finding, Test
from dojo.tools.venafi.parser import VenafiParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestVenafiParser(DojoTestCase):
    def parse(self, filename):
        path = get_unit_tests_scans_path("venafi") / filename
        with path.open(encoding="utf-8") as file:
            return list(VenafiParser().get_findings(file, Test()))

    def parse_string(self, payload):
        return list(VenafiParser().get_findings(io.StringIO(json.dumps(payload)), Test()))

    def cert(self, **overrides):
        row = {"id": "cert-1", "fingerprint": "FP1", "subjectCN": ["app.example.com"],
               "keyStrength": 2048, "encryptionType": "RSA", "signatureHashAlgorithm": "SHA256",
               "validityEnd": "2099-01-01T00:00:00Z", "selfSigned": False}
        row.update(overrides)
        return {"certificates": [row]}

    def in_days(self, days):
        """A timestamp the given number of days from now, so expiry tests do not go stale."""
        return (datetime.now(tz=UTC) + timedelta(days=days)).strftime("%Y-%m-%dT%H:%M:%SZ")

    def kinds(self, findings):
        return sorted(finding.vuln_id_from_tool for finding in findings)

    def test_scan_type_matches_the_connector_exactly(self):
        """
        Must equal the connector's ScanTypeName verbatim.

        Note the scan type names CyberArk, the product's current owner, while the directory and the
        connector package still say venafi - so it cannot be derived from either and has to be copied.
        """
        parser = VenafiParser()
        self.assertEqual(["CyberArk Certificate Manager Scan"], parser.get_scan_types())
        self.assertEqual("CyberArk Certificate Manager Scan",
                         parser.get_label_for_scan_types("CyberArk Certificate Manager Scan"))
        self.assertNotIn("Venafi Scan", parser.get_scan_types())

    def test_no_vuln(self):
        """A healthy certificate breaks no rule and produces no findings at all."""
        self.assertEqual(0, len(self.parse("venafi_no_vuln.json")))

    def test_one_vuln(self):
        self.assertEqual(1, len(self.parse("venafi_one_vuln.json")))

    def test_one_vuln_field_mapping(self):
        """Full field mapping, mirroring Convert in the connector's finding_converter."""
        findings = self.parse("venafi_one_vuln.json")
        self.assertEqual(1, len(findings))

        finding = findings[0]
        self.assertEqual("Certificate has expired (legacy.example.com)", finding.title)
        self.assertEqual("Critical", finding.severity)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        self.assertEqual("venafi-BB11CC22DD33EE44FF5500112233445566778899-expired",
                         finding.unique_id_from_tool)
        self.assertEqual("expired", finding.vuln_id_from_tool)
        self.assertEqual("legacy.example.com", finding.component_name)
        self.assertEqual("Renew the certificate and replace it on every deployment.",
                         finding.mitigation)
        self.assertTrue(finding.active)
        self.assertTrue(finding.static_finding)
        self.assertFalse(finding.dynamic_finding)
        self.assertEqual(["expired", "RSA"], finding.unsaved_tags)
        self.assertEqual(
            "**Finding:** The certificate expired on 2020-03-01T12:00:00Z.\n"
            "**Common name:** legacy.example.com\n"
            "**Subject alternative names:** legacy.example.com\n"
            "**Issuer:** Generic Issuing CA\n"
            "**Key:** RSA 4096 bits\n"
            "**Signature algorithm:** SHA256\n"
            "**Expires:** 2020-03-01T12:00:00Z\n"
            "**Fingerprint:** BB11CC22DD33EE44FF5500112233445566778899",
            finding.description,
        )

    def test_many_vuln(self):
        """
        Neither edition returns a compliance verdict, so the posture rules are computed.

        The fixture's first certificate breaks FOUR rules at once and the md5-signed one breaks a
        fifth; the elliptic-curve, healthy and attribute-less certificates break none.
        """
        findings = self.parse("venafi_many_vuln.json")
        self.assertEqual(5, len(findings))
        self.assertEqual(["expired", "self-signed", "weak-key", "weak-signature", "weak-signature"],
                         self.kinds(findings))

    def test_one_certificate_can_break_several_rules(self):
        findings = [f for f in self.parse("venafi_many_vuln.json")
                    if f.component_name == "legacy.example.com"]
        self.assertEqual(["expired", "self-signed", "weak-key", "weak-signature"],
                         self.kinds(findings))

    def test_severity_is_fixed_per_rule(self):
        by_kind = {f.vuln_id_from_tool: f for f in self.parse("venafi_many_vuln.json")}
        self.assertEqual("Critical", by_kind["expired"].severity)
        self.assertEqual("High", by_kind["weak-key"].severity)
        self.assertEqual("High", by_kind["weak-signature"].severity)
        self.assertEqual("Medium", by_kind["self-signed"].severity)

    def test_an_expiry_inside_thirty_days_is_reported_as_expiring_soon(self):
        findings = self.parse_string(self.cert(validityEnd=self.in_days(10)))
        self.assertEqual(1, len(findings))
        self.assertEqual("expiring-soon", findings[0].vuln_id_from_tool)
        self.assertEqual("High", findings[0].severity)
        self.assertEqual("Certificate expires within 30 days (app.example.com)", findings[0].title)
        self.assertEqual("Schedule renewal before the expiry date.", findings[0].mitigation)

    def test_an_expiry_beyond_thirty_days_is_not_reported(self):
        self.assertEqual(0, len(self.parse_string(self.cert(validityEnd=self.in_days(60)))))

    def test_an_expiry_in_the_past_is_expired_not_expiring(self):
        findings = self.parse_string(self.cert(validityEnd=self.in_days(-1)))
        self.assertEqual(["expired"], self.kinds(findings))

    def test_a_certificate_with_no_expiry_is_not_reported_either_way(self):
        """
        Guessing would either raise a false alarm or hide a real lapse.

        A rule is skipped when the attribute it needs is absent.
        """
        findings = [f for f in self.parse("venafi_many_vuln.json")
                    if f.component_name == "no-expiry.example.com"]
        self.assertEqual([], findings)

    def test_the_expiring_soon_detail_counts_the_days_remaining(self):
        findings = self.parse_string(self.cert(validityEnd=self.in_days(10)))
        self.assertIn("(in 9 days)", findings[0].description)

    def test_only_an_rsa_key_is_measured_against_the_2048_bit_floor(self):
        """
        An elliptic-curve key is much shorter by design.

        Applying the RSA floor to it would report every EC certificate as weak.
        """
        weak_rsa = self.parse_string(self.cert(encryptionType="RSA", keyStrength=1024))
        self.assertEqual(["weak-key"], self.kinds(weak_rsa))

        short_ec = self.parse_string(self.cert(encryptionType="EC", keyStrength=256))
        self.assertEqual([], self.kinds(short_ec))

    def test_the_ec_certificate_in_the_fixture_is_not_flagged(self):
        findings = [f for f in self.parse("venafi_many_vuln.json")
                    if f.component_name == "CN=internal.example.com,O=Generic Org"]
        self.assertEqual([], findings)

    def test_key_sizes(self):
        for size, kinds in ((512, ["weak-key"]), (1024, ["weak-key"]), (2047, ["weak-key"]),
                            (2048, []), (4096, []), (0, [])):
            with self.subTest(size=size):
                findings = self.parse_string(self.cert(keyStrength=size))
                self.assertEqual(kinds, self.kinds(findings))

    def test_a_quoted_key_size_is_accepted(self):
        findings = self.parse_string(self.cert(keyStrength="1024"))
        self.assertEqual(["weak-key"], self.kinds(findings))

    def test_weak_signature_hashes(self):
        """Hyphens are stripped first, so "SHA-1" and "SHA1" are both recognised."""
        for algorithm, weak in (("SHA1", True), ("SHA-1", True), ("sha1WithRSAEncryption", True),
                                ("MD5", True), ("md5WithRSAEncryption", True), ("MD2", True),
                                ("SHA256", False), ("SHA-256", False), ("SHA384", False),
                                ("", False)):
            with self.subTest(algorithm=algorithm):
                findings = self.parse_string(self.cert(signatureHashAlgorithm=algorithm))
                self.assertEqual(["weak-signature"] if weak else [], self.kinds(findings))

    def test_the_signature_algorithm_field_is_the_fallback_for_the_hash_field(self):
        """The fixture's md5 certificate names it only in signatureAlgorithm."""
        findings = [f for f in self.parse("venafi_many_vuln.json")
                    if f.component_name == "md5.example.com"]
        self.assertEqual(["weak-signature"], self.kinds(findings))
        self.assertIn("md5WithRSAEncryption", findings[0].title)

    def test_a_self_signed_certificate_is_reported(self):
        findings = self.parse_string(self.cert(selfSigned=True))
        self.assertEqual(["self-signed"], self.kinds(findings))
        self.assertEqual("Medium", findings[0].severity)

    def test_the_self_hosted_edition_is_read_too(self):
        """
        The self-hosted edition capitalises every field name, and sends no self-signed flag.

        Reading only the SaaS names would silently produce no findings at all against it, because every
        rule's attribute would look absent.
        """
        findings = self.parse("venafi_self_hosted.json")
        self.assertEqual(["expired", "self-signed", "weak-key", "weak-signature"],
                         self.kinds(findings))
        for finding in findings:
            with self.subTest(kind=finding.vuln_id_from_tool):
                self.assertEqual("legacy.example.com", finding.component_name)
                self.assertTrue(finding.unique_id_from_tool.startswith(
                    "venafi-FF11EE22DD33CC44BB5500112233445566778899-"))

    def test_the_self_hosted_edition_infers_self_signed_from_subject_and_issuer(self):
        """It has no flag, so a subject matching the issuer is what self-signed means."""
        matching = self.parse_string({"Certificates": [{
            "Thumbprint": "T1", "CN": "a.example.com", "Subject": "CN=a.example.com",
            "Issuer": "cn=a.example.com", "KeySize": 2048, "KeyAlgorithm": "RSA",
            "SignatureAlgorithm": "SHA256", "ValidTo": "2099-01-01T00:00:00"}]})
        self.assertEqual(["self-signed"], self.kinds(matching))

        differing = self.parse_string({"Certificates": [{
            "Thumbprint": "T2", "CN": "b.example.com", "Subject": "CN=b.example.com",
            "Issuer": "CN=Generic Issuing CA", "KeySize": 2048, "KeyAlgorithm": "RSA",
            "SignatureAlgorithm": "SHA256", "ValidTo": "2099-01-01T00:00:00"}]})
        self.assertEqual([], self.kinds(differing))

    def test_a_self_hosted_certificate_with_no_subject_is_not_self_signed(self):
        findings = self.parse_string({"Certificates": [{
            "Thumbprint": "T3", "CN": "c.example.com", "Subject": "", "Issuer": "",
            "KeySize": 2048, "KeyAlgorithm": "RSA", "SignatureAlgorithm": "SHA256",
            "ValidTo": "2099-01-01T00:00:00"}]})
        self.assertEqual([], self.kinds(findings))

    def test_the_saas_edition_sends_the_common_name_as_a_list(self):
        findings = self.parse_string(self.cert(subjectCN=["first.example.com", "second.example.com"],
                                              validityEnd=self.in_days(-1)))
        self.assertEqual("first.example.com", findings[0].component_name)

    def test_the_common_name_falls_back_to_the_subject_dn_then_the_fingerprint(self):
        findings = self.parse_string(self.cert(subjectCN=[], subjectDN="CN=dn.example.com",
                                              validityEnd=self.in_days(-1)))
        self.assertEqual("CN=dn.example.com", findings[0].component_name)

        findings = self.parse_string(self.cert(subjectCN=[], subjectDN="",
                                              validityEnd=self.in_days(-1)))
        self.assertEqual("FP1", findings[0].component_name)

    def test_the_identity_prefers_the_fingerprint_over_the_id(self):
        findings = self.parse_string(self.cert(validityEnd=self.in_days(-1)))
        self.assertEqual("venafi-FP1-expired", findings[0].unique_id_from_tool)

        findings = self.parse_string(self.cert(fingerprint="", validityEnd=self.in_days(-1)))
        self.assertEqual("venafi-cert-1-expired", findings[0].unique_id_from_tool)

    def test_subject_alternative_names_are_flattened_across_types_and_sorted(self):
        """
        Sorted, unlike the connector: it iterates a Go map, whose order is randomised.

        Sorting keeps a file import stable and readable. The line is not in the deduplication hash, so
        the two still match.
        """
        findings = self.parse_string(self.cert(
            subjectAlternativeNamesByType={
                "iPAddress": ["10.0.0.1"],
                "dNSName": ["zeta.example.com", "alpha.example.com"],
            },
            validityEnd=self.in_days(-1)))
        self.assertIn("**Subject alternative names:** 10.0.0.1, alpha.example.com, zeta.example.com",
                      findings[0].description)

    def test_an_empty_san_map_leaves_the_line_out(self):
        findings = self.parse_string(self.cert(subjectAlternativeNamesByType={},
                                              validityEnd=self.in_days(-1)))
        self.assertNotIn("**Subject alternative names:**", findings[0].description)

    def test_the_key_line_renders_whichever_half_is_known(self):
        cases = (
            ({"encryptionType": "RSA", "keyStrength": 4096}, "**Key:** RSA 4096 bits"),
            ({"encryptionType": "", "keyStrength": 4096}, "**Key:** 4096 bits"),
            ({"encryptionType": "RSA", "keyStrength": 0}, "**Key:** RSA"),
        )
        for overrides, expected in cases:
            with self.subTest(expected=expected):
                findings = self.parse_string(self.cert(validityEnd=self.in_days(-1), **overrides))
                self.assertIn(expected, findings[0].description)

    def test_timestamp_formats(self):
        """Every layout the connector accepts, including a date with no time at all."""
        for value in ("2020-03-01T12:00:00Z", "2020-03-01T12:00:00.000+0000",
                      "2020-03-01T12:00:00", "2020-03-01"):
            with self.subTest(value=value):
                findings = self.parse_string(self.cert(validityEnd=value))
                self.assertEqual(["expired"], self.kinds(findings))

    def test_an_unparseable_timestamp_reports_no_expiry_rule(self):
        findings = self.parse_string(self.cert(validityEnd="not a timestamp"))
        self.assertEqual([], self.kinds(findings))

    def test_export_shapes(self):
        row = {"fingerprint": "FP1", "subjectCN": ["app.example.com"],
               "validityEnd": "2020-01-01T00:00:00Z"}
        for payload in ([row], {"certificates": [row]}, {"data": [row]}, {"results": [row]}):
            with self.subTest(shape=str(payload)[:24]):
                self.assertEqual(1, len(self.parse_string(payload)))

    def test_non_object_export_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string("not an export")
        self.assertIn("CyberArk Certificate Manager", str(context.exception))

    def test_unrelated_json_is_rejected(self):
        with self.assertRaises(TypeError) as context:
            self.parse_string({"scanner": "something else"})
        self.assertIn("certificates", str(context.exception))

    def test_malformed_rows_are_skipped(self):
        findings = self.parse_string({"certificates": [
            "not an object",
            None,
            {"fingerprint": "FP9", "subjectCN": ["app.example.com"],
             "subjectAlternativeNamesByType": {"dNSName": "not a list"},
             "validityEnd": "2020-01-01T00:00:00Z"},
        ]})
        self.assertEqual(1, len(findings))
        self.assertEqual("venafi-FP9-expired", findings[0].unique_id_from_tool)
        self.assertNotIn("**Subject alternative names:**", findings[0].description)

    def test_the_certificate_is_the_component(self):
        """The same problem on two certificates stays two findings."""
        self.assertEqual(["title", "severity", "component_name"], VenafiParser().get_dedupe_fields())

    def test_severity_is_always_a_known_value(self):
        for filename in ("venafi_many_vuln.json", "venafi_one_vuln.json", "venafi_self_hosted.json"):
            for finding in self.parse(filename):
                with self.subTest(filename=filename, uid=finding.unique_id_from_tool):
                    self.assertIn(finding.severity, Finding.SEVERITIES)
