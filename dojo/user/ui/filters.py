from django_filters import CharFilter, OrderingFilter

from dojo.filters import DojoFilter
from dojo.models import Dojo_User


class UserFilter(DojoFilter):
    first_name = CharFilter(lookup_expr="icontains")
    last_name = CharFilter(lookup_expr="icontains")
    username = CharFilter(lookup_expr="icontains")
    email = CharFilter(lookup_expr="icontains")

    o = OrderingFilter(
        # tuple-mapping retains order
        fields=(
            ("username", "username"),
            ("last_name", "last_name"),
            ("first_name", "first_name"),
            ("email", "email"),
            ("is_active", "is_active"),
            ("is_superuser", "is_superuser"),
            ("is_staff", "is_staff"),
            ("date_joined", "date_joined"),
            ("last_login", "last_login"),
        ),
        field_labels={
            "username": "User Name",
            "is_active": "Active",
            "is_superuser": "Superuser",
            "is_staff": "Staff",
        },
    )

    class Meta:
        model = Dojo_User
        fields = ["is_superuser", "is_staff", "is_active", "first_name", "last_name", "username", "email"]
