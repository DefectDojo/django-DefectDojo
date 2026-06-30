from django.http import QueryDict

from dojo.filters import ProductFilter
from dojo.models import Product
from dojo.templatetags.filter_tags import has_active_filters
from unittests.dojo_test_case import DojoTestCase


class HasActiveFiltersTests(DojoTestCase):

    """
    Regression tests for the list-page filter panel auto-opening.

    The panel must auto-expand only when a real filter is applied, not when the
    user merely sorts a column. Column-header sort links write ?o=... into the
    same filter form, so plain form.has_changed() would treat sorting as
    filtering and pop the panel open. has_active_filters() ignores the ordering
    field so sorting alone leaves the panel closed.
    """

    def _form(self, query):
        return ProductFilter(QueryDict(query), queryset=Product.objects.none()).form

    def test_no_params_has_no_active_filters(self):
        self.assertFalse(has_active_filters(self._form("")))

    def test_ascending_sort_only_is_not_an_active_filter(self):
        self.assertFalse(has_active_filters(self._form("o=prod_type__name")))

    def test_descending_sort_only_is_not_an_active_filter(self):
        self.assertFalse(has_active_filters(self._form("o=-name")))

    def test_real_filter_is_active(self):
        self.assertTrue(has_active_filters(self._form("name=anything")))

    def test_filter_combined_with_sort_is_active(self):
        self.assertTrue(has_active_filters(self._form("name=anything&o=prod_type__name")))

    def test_none_form_is_not_active(self):
        self.assertFalse(has_active_filters(None))
