from django.contrib.auth import get_user_model
from django_filters import OrderingFilter
from django_filters import rest_framework as filters

from dojo.models import UserContactInfo

User = get_user_model()


class ApiUserFilter(filters.FilterSet):
    last_login = filters.DateFromToRangeFilter()
    date_joined = filters.DateFromToRangeFilter()
    is_active = filters.BooleanFilter()
    is_superuser = filters.BooleanFilter()
    username = filters.CharFilter(lookup_expr="icontains")
    first_name = filters.CharFilter(lookup_expr="icontains")
    last_name = filters.CharFilter(lookup_expr="icontains")
    email = filters.CharFilter(lookup_expr="icontains")

    class Meta:
        model = User
        fields = [
            "id",
            "username",
            "first_name",
            "last_name",
            "email",
            "is_active",
            "is_superuser",
            "last_login",
            "date_joined",
        ]

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("username", "username"),
            ("last_name", "last_name"),
            ("first_name", "first_name"),
            ("email", "email"),
            ("is_active", "is_active"),
            ("is_superuser", "is_superuser"),
            ("date_joined", "date_joined"),
            ("last_login", "last_login"),
        ),
    )


class ApiUserContactInfoFilter(filters.FilterSet):
    class Meta:
        model = UserContactInfo
        # user_state_details is an internal JSONField for UI state; django-filter
        # cannot auto-generate a filter for it, so exclude it (everything else
        # keeps the previous "__all__" auto-filter behaviour).
        exclude = ["user_state_details"]
