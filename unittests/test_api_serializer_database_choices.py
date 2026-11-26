"""
The import, reimport and user serializers read their database-backed options per request, not at import.

``scan_type`` leaves out the inactive ``Test_Type`` rows, and ``configuration_permissions`` follows the
``enable_github``, ``enable_jira`` and ``enable_questionnaires`` system settings. Both used to be computed in
the class body, so they held what the database said when the module was imported: a test type deactivated
afterwards stayed selectable, and a permission switched on afterwards stayed unknown, until a restart.
"""

from django.contrib.auth.models import Permission
from django.db import connection
from django.test.utils import CaptureQueriesContext
from rest_framework.exceptions import ValidationError

from dojo.api_v2.serializers import DeferredChoiceField, ImportScanSerializer, ReImportScanSerializer
from dojo.models import Test_Type
from dojo.user.api.serializer import UserSerializer
from unittests.dojo_test_case import DojoTestCase

SCAN_TYPE = "ZAP Scan"


class TestScanTypeChoicesPerRequest(DojoTestCase):

    def set_active(self, active):
        Test_Type.objects.update_or_create(name=SCAN_TYPE, defaults={"active": active})

    def test_choices_follow_test_type_rows_changed_after_import(self):
        for serializer_class in (ImportScanSerializer, ReImportScanSerializer):
            with self.subTest(serializer=serializer_class.__name__):
                self.set_active(active=False)
                self.assertNotIn(SCAN_TYPE, serializer_class().fields["scan_type"].choices)
                self.set_active(active=True)
                self.assertIn(SCAN_TYPE, serializer_class().fields["scan_type"].choices)

    def test_an_inactive_scan_type_is_refused(self):
        self.set_active(active=False)
        with self.assertRaises(ValidationError):
            ImportScanSerializer().fields["scan_type"].to_internal_value(SCAN_TYPE)
        self.set_active(active=True)
        self.assertEqual(SCAN_TYPE, ImportScanSerializer().fields["scan_type"].to_internal_value(SCAN_TYPE))

    def test_building_the_serializer_reads_nothing(self):
        with CaptureQueriesContext(connection) as queries:
            fields = ImportScanSerializer().fields
        self.assertEqual(0, len(queries), [query["sql"] for query in queries])
        self.assertTrue(fields["scan_type"]._deferred)


class TestDeferredChoiceField(DojoTestCase):

    def test_choices_are_read_once_when_first_needed(self):
        calls = []

        def source():
            calls.append(1)
            return [("a", "A"), ("b", "B")]

        field = DeferredChoiceField(source)
        self.assertEqual([], calls)
        self.assertEqual("a", field.to_internal_value("a"))
        self.assertEqual({"a": "A", "b": "B"}, dict(field.grouped_choices))
        self.assertEqual({"a": "A", "b": "B"}, dict(field.choices))
        self.assertEqual([1], calls)

    def test_setting_choices_replaces_the_source(self):
        def source():
            msg = "the source must not be read once choices are set"
            raise AssertionError(msg)

        field = DeferredChoiceField(source)
        field.choices = [("c", "C")]
        self.assertEqual({"c": "c"}, field.choice_strings_to_values)

    def test_each_serializer_instance_reads_its_own(self):
        Test_Type.objects.update_or_create(name=SCAN_TYPE, defaults={"active": True})
        first = ImportScanSerializer().fields["scan_type"]
        self.assertIn(SCAN_TYPE, first.choices)
        Test_Type.objects.filter(name=SCAN_TYPE).update(active=False)
        self.assertNotIn(SCAN_TYPE, ImportScanSerializer().fields["scan_type"].choices)
        # The declared field on the class is never resolved.
        self.assertTrue(ImportScanSerializer._declared_fields["scan_type"]._deferred)


class TestConfigurationPermissionsPerRequest(DojoTestCase):

    fixtures = ["dojo_testdata.json"]

    def codenames(self, serializer):
        field = serializer.fields["configuration_permissions"]
        self.assertEqual(list(field.queryset), list(field.child_relation.queryset))
        return set(field.child_relation.queryset.values_list("codename", flat=True))

    def test_queryset_follows_system_settings_changed_after_import(self):
        self.system_settings(enable_jira=False)
        self.assertNotIn("add_jira_instance", self.codenames(UserSerializer()))
        self.system_settings(enable_jira=True)
        self.assertIn("add_jira_instance", self.codenames(UserSerializer()))

    def test_a_permission_switched_on_after_import_is_accepted(self):
        self.system_settings(enable_jira=True)
        permission = Permission.objects.get(codename="add_jira_instance")
        field = UserSerializer().fields["configuration_permissions"]
        self.assertEqual([permission], field.to_internal_value([permission.id]))

    def test_building_the_serializer_reads_nothing(self):
        with CaptureQueriesContext(connection) as queries:
            UserSerializer()
        self.assertEqual(0, len(queries), [query["sql"] for query in queries])

    def test_the_declared_field_holds_no_query(self):
        self.assertFalse(UserSerializer._declared_fields["configuration_permissions"].child_relation.queryset.exists())
