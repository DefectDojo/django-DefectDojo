from rest_framework import mixins, viewsets
from rest_framework.permissions import DjangoModelPermissions

from dojo.api_v2.views import DeprecatedFieldsMixin
from dojo.authorization import api_permissions as permissions
from dojo.system_settings.api.serializer import SystemSettingsSerializer
from dojo.system_settings.models import System_Settings


# Authorization: superuser
class SystemSettingsViewSet(
    DeprecatedFieldsMixin, mixins.ListModelMixin, mixins.UpdateModelMixin, viewsets.GenericViewSet,
):

    """Basic control over System Settings. Use 'id' 1 for PUT, PATCH operations"""

    permission_classes = (permissions.IsSuperUser, DjangoModelPermissions)
    serializer_class = SystemSettingsSerializer
    queryset = System_Settings.objects.none()
    deprecated_fields = dict.fromkeys(
        (
            "enable_product_grade",
            "enforce_verified_status_product_grading",
            "product_grade_a",
            "product_grade_b",
            "product_grade_c",
            "product_grade_d",
            "product_grade_f",
        ),
        "product_grade",
    )

    def get_queryset(self):
        return System_Settings.objects.all().order_by("id")
