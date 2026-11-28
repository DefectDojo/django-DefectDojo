from django.core.exceptions import ValidationError
from django.template import Context, Template
from django.test import override_settings
from django.utils import timezone

from dojo.engagement.ui.filters import EngagementTestFilterWithoutObjectLookups
from dojo.models import Engagement, Product, Product_Type, System_Settings, Test
from dojo.system_settings import behaviour
from dojo.system_settings.behaviour import SETTING_FIELDS, get_setting, team_name
from dojo.utils import get_setting as utils_get_setting

from .dojo_test_case import DojoTestCase


class TestBehaviourSettings(DojoTestCase):

    """A behaviour setting reads the System Settings field when saved, else the DD_* setting."""

    def _save(self, **fields):
        row = System_Settings.objects.get(no_cache=True)
        for name, value in fields.items():
            setattr(row, name, value)
        row.save()

    def test_every_field_exists_and_starts_empty(self):
        row = System_Settings.objects.get(no_cache=True)
        for field in SETTING_FIELDS.values():
            self.assertIsNone(getattr(row, field), field)

    @override_settings(DELETE_PREVIEW=True, MAX_ALERTS_PER_USER=999)
    def test_an_empty_field_uses_the_setting(self):
        self.assertTrue(get_setting("DELETE_PREVIEW"))
        self.assertEqual(get_setting("MAX_ALERTS_PER_USER"), 999)
        self.assertTrue(utils_get_setting("DELETE_PREVIEW"))

    @override_settings(DELETE_PREVIEW=True, MAX_ALERTS_PER_USER=999)
    def test_a_saved_field_wins_over_the_setting(self):
        self._save(delete_preview=False, max_alerts_per_user=5)
        self.assertFalse(get_setting("DELETE_PREVIEW"))
        self.assertEqual(get_setting("MAX_ALERTS_PER_USER"), 5)
        self.assertFalse(utils_get_setting("DELETE_PREVIEW"))

    def test_a_setting_outside_the_family_is_the_django_setting(self):
        with override_settings(SOME_OTHER_SETTING="x"):
            self.assertEqual(get_setting("SOME_OTHER_SETTING"), "x")

    def test_finding_groups_reads_only_the_field(self):
        self._save(enable_finding_groups=False)
        with override_settings(FEATURE_FINDING_GROUPS=True):
            self.assertFalse(get_setting("FEATURE_FINDING_GROUPS"))

    def test_a_stored_map_is_merged_over_the_deployment_map(self):
        base = {"Scanner A": ["title"], "Scanner B": ["cwe"]}
        with override_settings(HASHCODE_FIELDS_PER_SCANNER=base):
            self._save(hashcode_fields_per_scanner={"Scanner B": ["title", "cwe"], "Scanner C": ["severity"]})
            merged = get_setting("HASHCODE_FIELDS_PER_SCANNER")
            self.assertEqual(merged, {"Scanner A": ["title"], "Scanner B": ["title", "cwe"], "Scanner C": ["severity"]})
            # The deployment's map is not changed in place.
            self.assertEqual(base, {"Scanner A": ["title"], "Scanner B": ["cwe"]})

    def test_the_merged_map_is_reused_while_nothing_changes(self):
        base = {"Scanner A": "hash_code"}
        overrides = {"Scanner B": "legacy"}
        first = behaviour._merge("DEDUPLICATION_ALGORITHM_PER_PARSER", base, overrides)
        self.assertIs(behaviour._merge("DEDUPLICATION_ALGORITHM_PER_PARSER", base, overrides), first)
        self.assertIsNot(behaviour._merge("DEDUPLICATION_ALGORITHM_PER_PARSER", base, {"Scanner B": "legacy"}), first)

    @override_settings(TEAM_NAME="Env Team")
    def test_team_name_prefers_the_field(self):
        self._save(team_name="")
        self.assertEqual(team_name(), "Env Team")
        self._save(team_name="Saved Team")
        self.assertEqual(team_name(), "Saved Team")

    @override_settings(DISABLE_FINDING_MERGE=False)
    def test_setting_enabled_filter_reads_the_field(self):
        template = Template("{% load display_tags %}{% if 'DISABLE_FINDING_MERGE'|setting_enabled %}off{% else %}on{% endif %}")
        self.assertEqual(template.render(Context({})), "on")
        self._save(disable_finding_merge=True)
        self.assertEqual(template.render(Context({})), "off")

    def test_validators_refuse_malformed_values(self):
        cases = [
            (behaviour.validate_hashcode_fields_per_scanner, {"Scanner": "title"}),
            (behaviour.validate_hashcode_fields_per_scanner, ["title"]),
            # A field outside HASHCODE_ALLOWED_FIELDS would let a saved map hash on anything.
            (behaviour.validate_hashcode_fields_per_scanner, {"Scanner": ["title", "not_an_allowed_field"]}),
            (behaviour.validate_deduplication_algorithm_per_parser, {"Scanner": "not-an-algorithm"}),
            (behaviour.validate_notifications_system_level_trump, "scan_added"),
        ]
        for validator, value in cases:
            with self.subTest(validator=validator.__name__, value=value), self.assertRaises(ValidationError):
                validator(value)

    def test_validators_accept_well_formed_and_empty_values(self):
        behaviour.validate_hashcode_fields_per_scanner({"Scanner": ["title", "cwe"]})
        behaviour.validate_deduplication_algorithm_per_parser({"Scanner": "hash_code"})
        behaviour.validate_notifications_system_level_trump(["scan_added"])
        for validator in (
            behaviour.validate_hashcode_fields_per_scanner,
            behaviour.validate_deduplication_algorithm_per_parser,
            behaviour.validate_notifications_system_level_trump,
        ):
            validator(None)

    @override_settings(MAX_ALERTS_PER_USER=999)
    def test_pinned_settings_resolve_each_name_once(self):
        with behaviour.pinned_settings():
            self.assertEqual(get_setting("MAX_ALERTS_PER_USER"), 999)
            self._save(max_alerts_per_user=5)
            # Pinned for the batch: the value read first holds until the block ends.
            self.assertEqual(get_setting("MAX_ALERTS_PER_USER"), 999)
            with behaviour.pinned_settings():
                self.assertEqual(get_setting("MAX_ALERTS_PER_USER"), 999)
        self.assertEqual(get_setting("MAX_ALERTS_PER_USER"), 5)


class TestEngagementTestFilterFollowsImportHistory(DojoTestCase):

    """The Reimported Version filter is offered only where the instance tracks import history, per request."""

    def setUp(self):
        product = Product.objects.create(name="Filter Product", description="x", prod_type=Product_Type.objects.create(name="Filter Type"))
        self.engagement = Engagement.objects.create(name="Filter Engagement", product=product, target_start=timezone.now(), target_end=timezone.now())

    def _filters(self):
        return EngagementTestFilterWithoutObjectLookups(
            {}, queryset=Test.objects.filter(engagement=self.engagement), engagement=self.engagement,
        ).filters

    def test_the_filter_follows_the_saved_setting(self):
        row = System_Settings.objects.get(no_cache=True)
        row.track_import_history = True
        row.save()
        self.assertIn("test_import__version", self._filters())
        row.track_import_history = False
        row.save()
        self.assertNotIn("test_import__version", self._filters())
        # The class keeps its declaration: the next instance that tracks history gets the filter back.
        row.track_import_history = True
        row.save()
        self.assertIn("test_import__version", self._filters())
