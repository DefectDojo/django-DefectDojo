from rest_framework import serializers

from dojo.models import CICDInfrastructure


class CICDInfrastructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = CICDInfrastructure
        fields = "__all__"

    def get_fields(self):
        fields = super().get_fields()
        if self.instance is not None:
            # Disallow editing of infra type on an instance; see the matching comment on CICDInfrastructure#save()
            fields["infrastructure_type"].read_only = True
        return fields
