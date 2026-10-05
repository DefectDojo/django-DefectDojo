import re
from datetime import date
from pathlib import Path
from unittest.mock import patch

from django.contrib import messages
from django.contrib.messages import get_messages
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import ImproperlyConfigured
from django.http import HttpResponse
from django.test import RequestFactory, SimpleTestCase
from django.utils import translation
from rest_framework.response import Response
from rest_framework.test import APIRequestFactory
from rest_framework.views import APIView

import dojo
import dojo.urls  # noqa: F401 -- loads every viewset module, so every DeprecationNoticeMixin subclass exists
from dojo.api_v2.views import DeprecationNoticeMixin
from dojo.decorators import deprecated_view
from dojo.deprecations import (
    Deprecation,
    active_deprecations,
    get_deprecation,
    overdue_deprecations,
    register_deprecation,
)
from dojo.product.ui import views as product_views
from dojo.tool_config.ui import views as tool_config_views
from dojo.tool_type.ui import views as tool_type_views

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


def ok_view(request):
    return HttpResponse("ok")


class TestDeprecatedView(SimpleTestCase):
    def shown(self, method):
        request = getattr(RequestFactory(), method)("/tool_type")
        request.session = {}
        request._messages = FallbackStorage(request)
        deprecated_view("tool_type")(ok_view)(request)
        return [(message.level, message.message, message.extra_tags) for message in get_messages(request)]

    def test_a_get_shows_the_declared_warning(self):
        self.assertEqual(
            [(messages.WARNING, get_deprecation("tool_type").message(), "alert-warning")],
            self.shown("get"),
        )

    def test_a_post_shows_nothing_so_the_redirect_does_not_repeat_it(self):
        self.assertEqual([], self.shown("post"))

    def test_an_undeclared_key_fails_at_import(self):
        with self.assertRaises(ImproperlyConfigured):
            deprecated_view("no_such_feature")

    def test_every_deprecated_classic_view_names_its_declaration(self):
        expected = {
            tool_type_views.new_tool_type: "tool_type",
            tool_type_views.edit_tool_type: "tool_type",
            tool_type_views.tool_type: "tool_type",
            tool_config_views.new_tool_config: "tool_configuration",
            tool_config_views.edit_tool_config: "tool_configuration",
            tool_config_views.tool_config: "tool_configuration",
            product_views.add_api_scan_configuration: "api_scan_configuration",
            product_views.view_api_scan_configurations: "api_scan_configuration",
            product_views.edit_api_scan_configuration: "api_scan_configuration",
            product_views.delete_api_scan_configuration: "api_scan_configuration",
        }
        for view, key in expected.items():
            with self.subTest(view=view.__name__):
                self.assertEqual(key, getattr(view, "deprecation", None))


class ToolTypeProbe(DeprecationNoticeMixin, APIView):
    authentication_classes = ()
    permission_classes = ()
    deprecation = "tool_type"

    def get(self, request):
        return Response({})


class UndeclaredProbe(ToolTypeProbe):
    deprecation = "no_such_feature"


class TestDeprecationHeaders(SimpleTestCase):
    def test_a_declared_feature_sends_both_headers_from_the_calendar(self):
        response = ToolTypeProbe.as_view()(APIRequestFactory().get("/"))
        self.assertEqual("True", response["X-Deprecated"])
        self.assertEqual("2026-11-02T00:00:00", response["X-End-Of-Life-Date"])

    def test_an_undeclared_key_sends_no_header(self):
        response = UndeclaredProbe.as_view()(APIRequestFactory().get("/"))
        self.assertFalse(response.has_header("X-Deprecated"))
        self.assertFalse(response.has_header("X-End-Of-Life-Date"))


HAND_TYPED_SCHEDULE = re.compile(
    r"removal_version=|removal_date=|end_of_life_date\s*=|will be removed (in|by) (DefectDojo )?v?\d|removal planned for \d",
)


def mixin_subclasses(cls):
    for sub in cls.__subclasses__():
        yield sub
        yield from mixin_subclasses(sub)


class TestEveryDeprecationKeyIsDeclared(SimpleTestCase):
    def test_a_mixin_subclass_never_names_an_undeclared_key(self):
        offenders = []
        for cls in mixin_subclasses(DeprecationNoticeMixin):
            if cls.__module__.startswith("unittests."):
                continue
            key = getattr(cls, "deprecation", "")
            if key and get_deprecation(key) is None:
                offenders.append(f"{cls.__module__}.{cls.__qualname__}: deprecation={key!r}")
        self.assertEqual([], offenders, "A typo here sends no deprecation header and fails silently.")


class TestNoHandTypedSchedule(SimpleTestCase):
    def test_only_the_registry_names_a_removal_release(self):
        root = Path(dojo.__file__).parent
        offenders = []
        for path in sorted([*root.rglob("*.py"), *root.rglob("*.html")]):
            if path.name == "deprecations.py" or "db_migrations" in path.parts:
                continue
            for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
                if HAND_TYPED_SCHEDULE.search(line):
                    offenders.append(f"{path.relative_to(root.parent)}:{number}")
        self.assertEqual([], offenders, "Declare the deprecation in dojo/deprecations.py and read it by key.")
