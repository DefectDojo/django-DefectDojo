
from django.test import TestCase, override_settings

from dojo.filters import FindingFilter
from dojo.models import Test_Type
from dojo.utils import get_visible_scan_types


class TestFindingFilterExcludesTestTypes(TestCase):
    def setUp(self):
        self.active_type = Test_Type.objects.create(name="Nessus Scan", active=True)
        self.excluded_type = Test_Type.objects.create(name="Inactive Scan", active=True)
        self.inactive_type = Test_Type.objects.create(name="Burp Scan", active=False)

    @override_settings(PARSER_EXCLUDE="Inactive Scan")
    def test_excludes_inactive_and_single_excluded(self):
        filter_instance = FindingFilter(data={})
        self.assertIn("test__test_type", filter_instance.form.fields)
        queryset = filter_instance.form.fields["test__test_type"].queryset
        actual_names = set(queryset.values_list("name", flat=True))
        self.assertIn(self.active_type.name, actual_names)
        self.assertNotIn(self.excluded_type.name, actual_names)
        self.assertNotIn(self.inactive_type.name, actual_names)

    @override_settings(PARSER_EXCLUDE="Inactive Scan|Acunetix Scan")
    def test_multiple_exclusions(self):
        filter_instance = FindingFilter(data={})
        queryset = filter_instance.form.fields["test__test_type"].queryset
        actual_names = set(queryset.values_list("name", flat=True))
        self.assertNotIn(self.excluded_type.name, actual_names)

    @override_settings(PARSER_EXCLUDE="")
    def test_no_exclusions_only_active(self):
        filter_instance = FindingFilter(data={})
        queryset = filter_instance.form.fields["test__test_type"].queryset
        self.assertIn(self.active_type, queryset)
        self.assertNotIn(self.inactive_type, queryset)

    def test_helper_function(self):
        visible = get_visible_scan_types()
        names = set(visible.values_list("name", flat=True))
        self.assertIn(self.active_type.name, names)
        self.assertNotIn(self.inactive_type.name, names)
