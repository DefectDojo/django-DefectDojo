from django_filters import BooleanFilter, NumberFilter
from django_filters.rest_framework import FilterSet

from dojo.labels import get_labels
from dojo.models import (
    Product_Type,
    Product_Type_Group,
    Product_Type_Member,
)

labels = get_labels()


class OrganizationFilterSet(FilterSet):
    critical_asset = BooleanFilter(field_name="critical_product")
    key_asset = BooleanFilter(field_name="key_product")

    class Meta:
        model = Product_Type
        fields = ("id", "name", "created", "updated")


class OrganizationMemberFilterSet(FilterSet):
    organization_id = NumberFilter(field_name="product_type_id")

    class Meta:
        model = Product_Type_Member
        fields = ("id", "user_id")


class OrganizationGroupFilterSet(FilterSet):
    asset_type_id = NumberFilter(field_name="product_type_id")

    class Meta:
        model = Product_Type_Group
        fields = ("id", "group_id")
