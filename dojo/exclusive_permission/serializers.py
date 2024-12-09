from rest_framework import serializers
from dojo.models import ExclusivePermission

class ExclusivePermissionSerializers(serializers.ModelSerializer):
    name = serializers.CharField(required=True,
                                 trim_whitespace=True,
                                 allow_blank=False,
                                 allow_null=False)
    description = serializers.CharField(required=True)

    class Meta:
        model = ExclusivePermission
        fields = "__all__"