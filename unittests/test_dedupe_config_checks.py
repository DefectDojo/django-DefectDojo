"""
Tests for the deduplication configuration system check.

The check guards the invariant that the two halves of a scan type's deduplication
registration agree. They are separate settings, and when only one of them is updated the
result is silent: the scan type keeps deduplicating, just not the way the configuration
says it does.
"""

from django.conf import settings
from django.test import SimpleTestCase, override_settings

from dojo.checks import check_configuration_deduplication


class TestDedupeConfigurationChecks(SimpleTestCase):

    def test_shipped_configuration_is_clean(self):
        """The registration DefectDojo ships must not trip its own check."""
        self.assertEqual(check_configuration_deduplication(None), [])

    @override_settings(
        HASHCODE_FIELDS_PER_SCANNER={"Some Scan": ["title", "severity"]},
        DEDUPLICATION_ALGORITHM_PER_PARSER={"Some Scan": "hash_code"},
    )
    def test_matched_registration_passes(self):
        self.assertEqual(check_configuration_deduplication(None), [])

    @override_settings(
        HASHCODE_FIELDS_PER_SCANNER={"Some Scan": ["title", "severity"]},
        DEDUPLICATION_ALGORITHM_PER_PARSER={},
    )
    def test_field_list_without_algorithm_warns(self):
        results = check_configuration_deduplication(None)
        self.assertEqual([r.id for r in results], ["dojo.W001"])
        self.assertIn("Some Scan", results[0].msg)

    @override_settings(
        # The exact shape of the Burp defect: the field list is keyed to a name no parser
        # produces, while the algorithm is keyed to the real one. Neither half applies.
        HASHCODE_FIELDS_PER_SCANNER={"Some Scan": ["title", "severity"]},
        DEDUPLICATION_ALGORITHM_PER_PARSER={"Some Scan Report": "hash_code"},
    )
    def test_split_registration_warns(self):
        results = check_configuration_deduplication(None)
        self.assertEqual([r.id for r in results], ["dojo.W001"])

    @override_settings(
        HASHCODE_FIELDS_PER_SCANNER={"Some Scan": ["not_a_finding_field"]},
        DEDUPLICATION_ALGORITHM_PER_PARSER={"Some Scan": "hash_code"},
    )
    def test_disallowed_field_still_errors(self):
        results = check_configuration_deduplication(None)
        self.assertEqual([r.id for r in results], ["dojo.E001"])

    def test_burp_suite_dast_scan_is_registered_under_its_parser_name(self):
        """
        The renamed Burp scan type must hash like the name it replaced.

        ``dojo/tools/burp_suite_dast`` answers to both "Burp Suite DAST Scan" and
        "Burp Enterprise Scan"; the same parser output must not get two identities.
        """
        fields = settings.HASHCODE_FIELDS_PER_SCANNER
        self.assertNotIn(
            "Burp Suite DAST", fields,
            "'Burp Suite DAST' is not a scan type any parser produces; the entry belongs to "
            "'Burp Suite DAST Scan'",
        )
        self.assertEqual(fields["Burp Suite DAST Scan"], fields["Burp Enterprise Scan"])
