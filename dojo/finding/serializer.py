from rest_framework import serializers

from dojo.finding.prisma_images_identity import PrismaIdentityMigrationType


class PrismaEngagementIdentityMigrationSerializer(serializers.Serializer):
    engagement_ids = serializers.ListField(child=serializers.IntegerField(min_value=1), required=False,
                                           allow_empty=False, max_length=100)
    after_engagement_id = serializers.IntegerField(min_value=0, default=0)
    limit = serializers.IntegerField(min_value=1, max_value=50, default=10)
    dry_run = serializers.BooleanField(default=True)
    migration_type = serializers.ChoiceField(
        choices=PrismaIdentityMigrationType.choices,
        default=PrismaIdentityMigrationType.DEPLOYMENT_CONTAINER_NAME,
        help_text="Target custom ID format: ID uses Cloud Id (or impact Image ID); "
                  "DeploymentContainerName updates runtime deployments and container names in description and impact. "
                  "ID removes both fields from description and impact and does not query the Search Engine.",
    )


class IARecommendationSerializer(serializers.Serializer):
    status = serializers.CharField(required=False)
    data = serializers.JSONField()

    def validate_data(self, value):
        if "like_status" in value:
            if (
                value["like_status"] == True or
                value["like_status"] == False
            ):
                return value
        raise serializers.ValidationError("like_status requiered (false or true)")



class RecommendationSerializer(serializers.Serializer):
    like_status = serializers.BooleanField(required=False,
                                           allow_null=True,
                                           default=None)
    recommendations = serializers.ListField(child=serializers.CharField())
    mitigations = serializers.ListField(child=serializers.CharField())
    files_to_fix = serializers.ListField(child=serializers.CharField())

class FindingBulkUpdateSLAStartDateSerializer(serializers.Serializer):
    tags = serializers.CharField(max_length=200)
    priority_classification = serializers.CharField(
        help_text="Comma-separated priority labels. Valid values: Unknown, Medium Low, High, Critical, Very Critical",
    )
    date = serializers.DateField()

    VALID_PRIORITY_VALUES = {"Unknown", "Medium Low", "High", "Critical", "Very Critical"}

    def validate_priority_classification(self, value):
        priorities = [p.strip() for p in value.split(",") if p.strip()]
        invalid = [p for p in priorities if p not in self.VALID_PRIORITY_VALUES]
        if invalid:
            raise serializers.ValidationError(
                f"Invalid priority values: {invalid}. "
                f"Valid values are: {sorted(self.VALID_PRIORITY_VALUES)}"
            )
        return value
