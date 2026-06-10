from rest_framework import serializers

from dojo.models import CICDInfrastructure


class CICDInfrastructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = CICDInfrastructure
        fields = "__all__"
