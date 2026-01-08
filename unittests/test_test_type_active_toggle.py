
from django.test import TestCase

from dojo.filters import FindingFilter
from dojo.models import Test_Type
from dojo.utils import get_visible_scan_types


class TestFindingFilterActiveInactiveTestTypes(TestCase):
    def setUp(self):
        self.active_type = Test_Type.objects.create(name="Nessus Scan", active=True)
        self.inactive_type = Test_Type.objects.create(name="Burp Scan", active=False)

    def test_only_active_types_in_filter(self):
        filter_instance = FindingFilter(data={})
        self.assertIn("test__test_type", filter_instance.form.fields)
        queryset = filter_instance.form.fields["test__test_type"].queryset
        actual_names = set(queryset.values_list("name", flat=True))
        self.assertIn(self.active_type.name, actual_names)
        self.assertNotIn(self.inactive_type.name, actual_names)

    def test_helper_function_returns_only_active(self):
        visible = get_visible_scan_types()
        names = set(visible.values_list("name", flat=True))
        self.assertIn(self.active_type.name, names)
        self.assertNotIn(self.inactive_type.name, names)
