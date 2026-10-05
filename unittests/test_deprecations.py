from datetime import date
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import translation

import dojo
from dojo.deprecations import (
    Deprecation,
    active_deprecations,
    get_deprecation,
    overdue_deprecations,
    register_deprecation,
)

UPGRADING_3_2 = "https://docs.defectdojo.com/releases/os_upgrading/3.2/"


def widgets(**overrides):
    fields = {"key": "widgets", "title": "Widgets", "removal_version": "3.5.0", "notice_url": "https://example.test"}
    fields.update(overrides)
    return Deprecation(**fields)


class TestDeprecationSchedule(SimpleTestCase):
    def test_the_date_comes_from_the_release_calendar(self):
        self.assertEqual(date(2026, 11, 2), widgets().removal_date)

    def test_people_read_the_version_and_the_month(self):
        self.assertEqual("3.5.0 (November 2026)", widgets().removal_label)

    def test_a_patch_release_is_refused(self):
        with self.assertRaisesRegex(ValueError, "minor release"):
            register_deprecation(widgets(key="widgets_patch", removal_version="3.5.100"))

    def test_a_release_missing_from_the_calendar_is_refused(self):
        with self.assertRaisesRegex(ValueError, "RELEASE_DATES"):
            register_deprecation(widgets(key="widgets_far", removal_version="9.9.0"))

    def test_a_second_registration_does_not_replace_the_first_unless_asked(self):
        first, second = widgets(), widgets(title="Gadgets")
        with patch.dict("dojo.deprecations._DEPRECATIONS", {}, clear=True):
            register_deprecation(first)
            register_deprecation(second)
            self.assertIs(first, get_deprecation("widgets"))
            register_deprecation(second, override=True)
            self.assertIs(second, get_deprecation("widgets"))

    def test_a_removed_feature_is_not_active(self):
        gone = widgets(key="gone", removal_version="3.3.0", removed=True)
        with patch.dict("dojo.deprecations._DEPRECATIONS", {"gone": gone}, clear=True):
            self.assertEqual([], active_deprecations())


class TestOverdue(SimpleTestCase):
    def test_a_declaration_past_its_release_is_overdue(self):
        old = widgets(removal_version="3.4.0")
        with patch.dict("dojo.deprecations._DEPRECATIONS", {"widgets": old}, clear=True):
            self.assertEqual([old], overdue_deprecations("3.5.0-dev"))
            self.assertEqual([], overdue_deprecations("3.4.0-dev"))
            self.assertEqual([], overdue_deprecations("3.4.0"))

    def test_a_removed_declaration_is_never_overdue(self):
        gone = widgets(removal_version="3.3.0", removed=True)
        with patch.dict("dojo.deprecations._DEPRECATIONS", {"gone": gone}, clear=True):
            self.assertEqual([], overdue_deprecations("3.6.0-dev"))

    def test_nothing_declared_is_overdue_on_this_release_line(self):
        overdue = [entry.key for entry in overdue_deprecations(dojo.__version__)]
        self.assertEqual(
            [],
            overdue,
            f"These removals are past their release on {dojo.__version__}. For each key, remove the feature and "
            "delete its declaration, set removed=True while a migration path remains, or move removal_version to "
            "a later release in dojo/deprecations.py.",
        )


class TestOpenSourceDeclarations(SimpleTestCase):
    def test_the_pull_parser_features_go_in_3_5_0(self):
        for key in ("tool_type", "tool_configuration", "api_scan_configuration"):
            with self.subTest(key=key):
                entry = get_deprecation(key)
                self.assertEqual("3.5.0", entry.removal_version)
                self.assertEqual(UPGRADING_3_2, entry.notice_url)

    def test_the_classic_message_uses_one_sentence_and_one_date_form(self):
        self.assertEqual(
            "Tool Types are deprecated and will be removed in DefectDojo 3.5.0 (November 2026). "
            "Please plan to migrate away from this feature.",
            get_deprecation("tool_type").message(),
        )

    def test_the_classic_message_never_mixes_two_languages(self):
        with translation.override("de"):
            message = get_deprecation("tool_type").message()
        self.assertTrue(message.startswith("Tool Types are deprecated"), message)
