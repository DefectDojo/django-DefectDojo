from django_filters.rest_framework import DjangoFilterBackend
from dojo.exclusive_permission.serializers import ExclusivePermissionSerializers
from dojo.api_v2.views import PrefetchDojoModelViewSet
from dojo.models import ExclusivePermission

class ExclusivePermissionViewSet(
    PrefetchDojoModelViewSet,
):
    serializer_class = ExclusivePermissionSerializers
    queryset = ExclusivePermission.objects.all()
    filter_backends = (DjangoFilterBackend,)
    filterset_fields = ["id", "name"]