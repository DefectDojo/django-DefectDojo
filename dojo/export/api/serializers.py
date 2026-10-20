import base64
import mimetypes

from rest_framework import serializers

from dojo.endpoint.api.serializer import EndpointStatusSerializer
from dojo.engagement.api.serializer import EngagementSerializer
from dojo.finding.api.serializer import FindingSerializer
from dojo.location.api.serializers import LocationFindingReferenceSerializer
from dojo.location.feature import locations_enabled
from dojo.models import FileUpload, Finding, Risk_Acceptance
from dojo.notes.api.serializer import NoteSerializer
from dojo.product.api.serializer import ProductSerializer
from dojo.product_type.api.serializer import ProductTypeSerializer
from dojo.risk_acceptance.api.serializer import RiskAcceptanceSerializer
from dojo.test.api.serializer import TestSerializer
from dojo.user.api.serializer import UserContactInfoSerializer, UserSerializer

MAX_FILE_BYTES_DEFAULT = 10485760


def _file_payload(field_file, max_file_bytes: int) -> dict:
    name = field_file.name
    payload = {"size": None, "content_type": mimetypes.guess_type(name)[0], "data_base64": None}
    if not name or not field_file.storage.exists(name):
        payload["error"] = "missing"
        return payload
    payload["size"] = field_file.storage.size(name)
    if payload["size"] <= max_file_bytes:
        with field_file.open("rb") as handle:
            payload["data_base64"] = base64.b64encode(handle.read()).decode("ascii")
    return payload


def export_file(file_upload: FileUpload, max_file_bytes: int) -> dict:
    return {"id": file_upload.id, "title": file_upload.title, **_file_payload(file_upload.file, max_file_bytes)}


def export_proof(risk_acceptance: Risk_Acceptance, max_file_bytes: int) -> dict | None:
    if not risk_acceptance.path:
        return None
    return {"filename": risk_acceptance.filename(), **_file_payload(risk_acceptance.path, max_file_bytes)}


def export_endpoint_entries(finding: Finding, status: serializers.Serializer, *, locations: bool) -> list[dict]:
    if locations:
        return [
            {
                "id": reference.location.id,
                "uri": reference.location.location_value,
                "location_type": reference.location.location_type,
                "tags": [tag.name for tag in reference.location.tags.all()],
                "status": status.to_representation(reference),
            }
            for reference in finding.locations.all()
        ]
    return [
        {
            "id": row.endpoint.id,
            "uri": str(row.endpoint),
            "location_type": None,
            "tags": [tag.name for tag in row.endpoint.tags.all()],
            "status": status.to_representation(row),
        }
        for row in finding.status_finding.all()
    ]


class ExportFilesMixin(serializers.Serializer):
    files = serializers.SerializerMethodField()

    def get_files(self, obj) -> list[dict]:
        return [export_file(file_upload, self.context["max_file_bytes"]) for file_upload in obj.files.all()]


class ExportProductSerializer(ProductSerializer):
    findings_count = None
    findings_list = None
    prod_type = ProductTypeSerializer(read_only=True)


class ExportEngagementSerializer(ExportFilesMixin, EngagementSerializer):
    pass


class ExportTestSerializer(ExportFilesMixin, TestSerializer):
    pass


class ExportFindingSerializer(ExportFilesMixin, FindingSerializer):
    accepted_risks = None
    related_fields = None
    risk_acceptances = serializers.PrimaryKeyRelatedField(source="risk_acceptance_set", many=True, read_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # FindingSerializer.__init__ replaces "endpoints" after get_fields, so a declared field would not survive.
        self.fields["endpoints"] = serializers.SerializerMethodField()
        self._locations = locations_enabled()
        self._endpoint_status = LocationFindingReferenceSerializer() if self._locations else EndpointStatusSerializer()

    def get_endpoints(self, obj) -> list[dict]:
        return export_endpoint_entries(obj, self._endpoint_status, locations=self._locations)


class ExportRiskAcceptanceSerializer(RiskAcceptanceSerializer):
    path = None
    proof = serializers.SerializerMethodField()
    engagement = serializers.PrimaryKeyRelatedField(read_only=True)
    notes = NoteSerializer(many=True, read_only=True)

    class Meta:
        model = Risk_Acceptance
        exclude = ("path",)

    def get_proof(self, obj) -> dict | None:
        return export_proof(obj, self.context["max_file_bytes"])


class ExportUserContactInfoSerializer(UserContactInfoSerializer):
    user_profile = None


class ExportUserSerializer(UserSerializer):
    password = None
    configuration_permissions = None
    contact_info = ExportUserContactInfoSerializer(source="usercontactinfo", read_only=True, allow_null=True)

    class Meta(UserSerializer.Meta):
        fields = (
            *(name for name in UserSerializer.Meta.fields if name not in {"password", "configuration_permissions"}),
            "contact_info",
        )

    def to_representation(self, instance):
        # Skip UserSerializer.to_representation: it reads the configuration_permissions key this class drops.
        return serializers.ModelSerializer.to_representation(self, instance)
