from django_filters import BooleanFilter
from django_filters.rest_framework import FilterSet

from dojo.labels import get_labels
from dojo.models import Product_Type

labels = get_labels()


class OrganizationFilterSet(FilterSet):
    critical_asset = BooleanFilter(field_name="critical_product")
    key_asset = BooleanFilter(field_name="key_product")

    class Meta:
        model = Product_Type
        fields = ("id", "name", "created", "updated")
