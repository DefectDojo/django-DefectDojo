import json

from django.urls import reverse
from rest_framework import serializers

from dojo.jira import services as jira_services
from dojo.jira.queries import get_authorized_jira_projects
from dojo.models import (
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
)


class JIRAIssueSerializer(serializers.ModelSerializer):
    url = serializers.SerializerMethodField(read_only=True)

    class Meta:
        model = JIRA_Issue
        fields = "__all__"

    def get_fields(self):
        fields = super().get_fields()
        # The jira_project relation is writable, so restrict the choosable
        # projects to the ones the caller is allowed to edit. Otherwise the
        # field would resolve any project id from the full manager on write.
        jira_project_field = fields.get("jira_project")
        user = getattr(self.context.get("request"), "user", None)
        # Only narrow for a real authenticated request. An anonymous/absent
        # user (e.g. OpenAPI schema generation) keeps the default queryset and
        # must not be handed to the authorization filter.
        if jira_project_field is not None and user is not None and not user.is_anonymous:
            jira_project_field.queryset = get_authorized_jira_projects("edit", user=user)
        return fields

    def get_url(self, obj) -> str:
        return jira_services.get_issue_url(obj)

    def validate(self, data):
        if self.context["request"].method == "PATCH":
            engagement = data.get("engagement", self.instance.engagement)
            finding = data.get("finding", self.instance.finding)
            finding_group = data.get(
                "finding_group", self.instance.finding_group,
            )
        else:
            engagement = data.get("engagement", None)
            finding = data.get("finding", None)
            finding_group = data.get("finding_group", None)

        if (
            (engagement and not finding and not finding_group)
            or (finding and not engagement and not finding_group)
            or (finding_group and not engagement and not finding)
        ):
            pass
        else:
            msg = "Either engagement or finding or finding_group has to be set."
            raise serializers.ValidationError(msg)

        if finding:
            if (linked_finding := jira_services.already_linked(finding, data.get("jira_key"), data.get("jira_id"))) is not None:
                msg = "JIRA issue " + data.get("jira_key") + " already linked to " + reverse("view_finding", args=(linked_finding.id,))
                raise serializers.ValidationError(msg)

        return data


class JIRAInstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Instance
        fields = "__all__"
        extra_kwargs = {
            "password": {"write_only": True},
        }


class JIRAProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Project
        fields = "__all__"

    def validate(self, data):
        if self.context["request"].method == "PATCH":
            engagement = data.get("engagement", self.instance.engagement)
            product = data.get("product", self.instance.product)
        else:
            engagement = data.get("engagement", None)
            product = data.get("product", None)

        if (engagement and product) or (not engagement and not product):
            msg = "Either engagement or product has to be set."
            raise serializers.ValidationError(msg)

        for json_field in ("custom_fields", "close_transition_fields", "reopen_transition_fields"):
            if json_field in data and isinstance(data[json_field], str):
                try:
                    data[json_field] = json.loads(data[json_field])
                except json.JSONDecodeError as e:
                    raise serializers.ValidationError({json_field: f"Invalid JSON: {e}"}) from e

        return data


class EngagementUpdateJiraEpicSerializer(serializers.Serializer):
    epic_name = serializers.CharField(required=False, max_length=200)
    epic_priority = serializers.CharField(required=False, allow_null=True)
