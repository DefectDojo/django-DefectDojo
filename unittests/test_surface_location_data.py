from dojo.tools.locations import LocationData
from unittests.dojo_test_case import DojoTestCase


class TestSurfaceLocationData(DojoTestCase):
    def test_domain_factory_emits_the_name_and_its_apex(self):
        location = LocationData.domain(fqdn="WWW.Example.com.", apex="example.com")
        self.assertEqual("domain", location.type)
        # Reported as given: normalizing the name is the consumer's job, so every parser
        # emits the same shape whatever case or trailing dot its tool used.
        self.assertEqual({"fqdn": "WWW.Example.com.", "apex": "example.com"}, location.data)

    def test_domain_factory_defaults_the_apex_to_empty(self):
        self.assertEqual({"fqdn": "api.example.com", "apex": ""}, LocationData.domain(fqdn="api.example.com").data)

    def test_ip_factory_emits_exactly_five_keys(self):
        location = LocationData.ip(address="192.0.2.10")
        self.assertEqual("ip", location.type)
        self.assertEqual(
            {"address": "192.0.2.10", "asn": None, "asn_organization": "", "network": "", "provider": ""},
            location.data,
        )

    def test_ip_factory_carries_what_the_tool_knows(self):
        location = LocationData.ip(
            address="2001:db8::1",
            asn=64500,
            asn_organization="Example Net",
            network="2001:db8::/32",
            provider="aws",
        )
        self.assertEqual(64500, location.data["asn"])
        self.assertEqual("2001:db8::/32", location.data["network"])
        self.assertEqual("aws", location.data["provider"])

    def test_cert_factory_emits_exactly_seven_keys(self):
        fingerprint = "ab" * 32
        location = LocationData.cert(
            sha256=fingerprint,
            subject_cn="example.com",
            sans=["example.com", "www.example.com"],
        )
        self.assertEqual("cert", location.type)
        self.assertEqual(
            {
                "sha256": fingerprint,
                "subject_cn": "example.com",
                "issuer": "",
                "serial_number": "",
                "not_before": "",
                "not_after": "",
                "sans": ["example.com", "www.example.com"],
            },
            location.data,
        )

    def test_cert_factory_copies_the_names_it_is_given(self):
        sans = ["example.com"]
        location = LocationData.cert(sha256="ab" * 32, sans=sans)
        sans.append("later.example.com")
        self.assertEqual(["example.com"], location.data["sans"])
        self.assertEqual([], LocationData.cert(sha256="ab" * 32).data["sans"])
