from rest_framework import serializers

from dojo.authorization.authorization import user_has_configuration_permission
from dojo.models import CICDInfrastructure

# Identity is readable by anyone so engagement pickers can offer the choices;
# these describe the infrastructure itself and need the view permission.
CICD_DETAIL_FIELDS = ("description", "url")


def user_can_view_cicd_detail(user) -> bool:
    # Change implies read: the edit form round-trips these fields, so withholding
    # them from an editor's payload would let a save blank them out.
    return (
        user_has_configuration_permission(user, "dojo.view_cicdinfrastructure")
        or user_has_configuration_permission(user, "dojo.change_cicdinfrastructure")
    )


def drop_cicd_detail_fields(serializer, fields):
    """Remove the detail fields unless the requesting user holds the view permission."""
    request = serializer.context.get("request")
    # No request means no caller to authorize (schema generation); leave the shape alone.
    if request is None or user_can_view_cicd_detail(request.user):
        return fields
    for name in CICD_DETAIL_FIELDS:
        fields.pop(name, None)
    return fields


class CICDInfrastructureSerializer(serializers.ModelSerializer):
    class Meta:
        model = CICDInfrastructure
        fields = "__all__"

    def get_fields(self):
        fields = super().get_fields()
        if self.instance is not None:
            # Disallow editing of infra type on an instance; see the matching comment on CICDInfrastructure#save()
            fields["infrastructure_type"].read_only = True
        return drop_cicd_detail_fields(self, fields)
