import base64
import mimetypes
from datetime import datetime
from operator import attrgetter
from pathlib import Path

from auditlog.models import LogEntry
from django.apps import apps
from django.conf import settings
from django.contrib.auth.models import Permission
from django.db.models import Prefetch, prefetch_related_objects
from django.db.models.fields.files import FieldFile
from rest_framework import serializers

from dojo.endpoint.api.serializer import EndpointStatusSerializer
from dojo.engagement.api.serializer import EngagementSerializer
from dojo.finding.api.serializer import BurpRawRequestResponseMultiSerializer, FindingSerializer
from dojo.github.models import GITHUB_Conf, GITHUB_PKey
from dojo.location.api.serializers import LocationFindingReferenceSerializer
from dojo.location.feature import locations_enabled
from dojo.models import (
    Announcement,
    Answer,
    Answered_Survey,
    BannerConf,
    Benchmark_Category,
    Benchmark_Product,
    Benchmark_Requirement,
    Benchmark_Type,
    Check_List,
    Choice,
    ChoiceAnswer,
    ChoiceQuestion,
    Contact,
    Engagement_Presets,
    Engagement_Survey,
    FileUpload,
    Finding,
    General_Survey,
    JIRA_Instance,
    JIRA_Issue,
    JIRA_Project,
    Objects_Product,
    Product_API_Scan_Configuration,
    Question,
    Report_Type,
    Risk_Acceptance,
    Sonarqube_Issue,
    Test_Import,
    Test_Type,
)
from dojo.notes.api.serializer import NoteSerializer
from dojo.product.api.serializer import ProductSerializer
from dojo.product_type.api.serializer import ProductTypeSerializer
from dojo.risk_acceptance.api.serializer import RiskAcceptanceSerializer
from dojo.test.api.serializer import TestSerializer
from dojo.tool_config.api.serializer import ToolConfigurationSerializer
from dojo.tool_config.models import Tool_Configuration
from dojo.user.api.serializer import UserContactInfoSerializer, UserSerializer
from dojo.user.utils import get_configuration_permissions_fields

MAX_FILE_BYTES_DEFAULT = 10485760
MAX_FILE_BYTES_LIMIT = 104857600
MAX_INLINE_BYTES_PER_LINE = 50331648
CHECK_LIST_ISSUE_FIELDS = (
    "session_issues", "crypto_issues", "config_issues", "auth_issues", "author_issues", "data_issues",
    "sensitive_issues", "other_issues",
)


render_datetime = serializers.DateTimeField().to_representation


class ExportParamsSerializer(serializers.Serializer):
    max_file_bytes = serializers.IntegerField(
        min_value=0,
        max_value=MAX_FILE_BYTES_LIMIT,
        default=MAX_FILE_BYTES_DEFAULT,
        help_text=(
            f"File size cap in bytes, at most {MAX_FILE_BYTES_LIMIT}. The product export carries a file of this "
            "size or less inline as base64. A larger file keeps its size with no data. The manifest counts larger "
            f"files in files_over_cap. The files of one line carry at most {MAX_INLINE_BYTES_PER_LINE // 2**20} MiB "
            "of base64 text in all. A file past that has no data and the error line_cap."
        ),
    )
    import_history = serializers.BooleanField(
        default=False,
        help_text=(
            "Add the import history of the product to the stream, and its counts to the manifest. The stream "
            "sends test_import lines, each followed by test_import_actions lines, after the risk acceptances."
        ),
    )
    audit_history = serializers.BooleanField(
        default=False,
        help_text=(
            "Add the audit history of the product to the stream, and its counts to the manifest. The stream "
            "sends audit_event lines, then legacy_audit_entry lines, after the import history."
        ),
    )
    product_extras = serializers.BooleanField(
        default=False,
        help_text=(
            "Add the tracking files, benchmark results, answered questionnaires and endpoints of the product to the "
            "stream. Add the counts of the first three to the manifest. The stream sends tracking_file, benchmark, "
            "answered_survey and product_endpoint lines after the risk acceptances."
        ),
    )
    jira = serializers.BooleanField(
        default=False,
        help_text=(
            "Add the Jira projects and issue links of the product to the stream, and the Jira instances and the "
            "counts of projects and issues to the manifest. The header holds the product projects. Engagement lines "
            "hold their project and issue. Finding lines hold their issue. No password crosses."
        ),
    )
    external_issues = serializers.BooleanField(
        default=False,
        help_text=(
            "Add the GitHub projects, GitHub issue links and SonarQube issues of the product to the stream, and the "
            "GitHub configurations and the counts of projects and issues to the manifest. The header holds the "
            "product GitHub projects. Finding lines hold their GitHub issue and their SonarQube issue with its "
            "transitions. No GitHub API key crosses."
        ),
    )


class ManifestParamsSerializer(ExportParamsSerializer):
    file_counts = serializers.BooleanField(
        default=True,
        help_text=(
            "Count files_over_cap by reading the size of every file in storage. With false the manifest skips "
            "that read, and files_over_cap is null."
        ),
    )


def file_size(storage, name: str) -> int | None:
    if not name:
        return None
    try:
        return storage.size(name)
    # uwsgi under an ASCII locale cannot encode a non-ASCII file name.
    except (FileNotFoundError, UnicodeError):
        return None


class InlineBudget:
    def __init__(self):
        self.left = MAX_INLINE_BYTES_PER_LINE

    def take(self, size: int) -> bool:
        cost = 4 * -(-size // 3)
        if cost > self.left:
            return False
        self.left -= cost
        return True


def _file_payload(field_file, max_file_bytes: int, budget: InlineBudget) -> dict:
    size = file_size(field_file.storage, field_file.name)
    payload = {"size": size, "content_type": mimetypes.guess_type(field_file.name)[0], "data_base64": None}
    if size is None:
        payload["error"] = "missing"
    elif size <= max_file_bytes:
        if budget.take(size):
            with field_file.open("rb") as handle:
                payload["data_base64"] = base64.b64encode(handle.read()).decode("ascii")
        else:
            payload["error"] = "line_cap"
    return payload


def threat_model_file(engagement) -> Path | None:
    """The threat model path of an engagement, or None when it has none."""
    return Path(engagement.tmodel_path) if engagement.tmodel_path not in {None, "", "none"} else None


def readable_threat_model(path: Path) -> Path | None:
    """The resolved path when it is a file inside MEDIA_ROOT, else None."""
    try:
        resolved = path.resolve()
        inside = resolved.is_relative_to(Path(settings.MEDIA_ROOT).resolve())
        return resolved if inside and resolved.is_file() else None
    except (ValueError, OSError):
        return None


def configuration_permission_names() -> set[str]:
    wanted = {f"{field.app}.{codename}" for field in get_configuration_permissions_fields() for codename in field.codenames()}
    rows = Permission.objects.filter(codename__in={name.split(".")[1] for name in wanted}).values_list(
        "content_type__app_label", "codename",
    )
    return {name for app_label, codename in rows if (name := f"{app_label}.{codename}") in wanted}


def export_threat_model(engagement, max_file_bytes: int, budget: InlineBudget) -> dict | None:
    path = threat_model_file(engagement)
    if path is None:
        return None
    payload = {"filename": path.name, "size": None, "content_type": mimetypes.guess_type(path.name)[0], "data_base64": None}
    resolved = readable_threat_model(path)
    if resolved is None:
        payload["error"] = "missing"
        return payload
    payload["size"] = resolved.stat().st_size
    if payload["size"] <= max_file_bytes:
        if budget.take(payload["size"]):
            payload["data_base64"] = base64.b64encode(resolved.read_bytes()).decode("ascii")
        else:
            payload["error"] = "line_cap"
    return payload


def export_file(file_upload: FileUpload, max_file_bytes: int, budget: InlineBudget | None = None) -> dict:
    return {
        "id": file_upload.id,
        "title": file_upload.title,
        "filename": Path(file_upload.file.name).name,
        **_file_payload(file_upload.file, max_file_bytes, budget or InlineBudget()),
    }


def export_proof(risk_acceptance: Risk_Acceptance, max_file_bytes: int) -> dict | None:
    if not risk_acceptance.path:
        return None
    return {"filename": risk_acceptance.filename(), **_file_payload(risk_acceptance.path, max_file_bytes, InlineBudget())}


def export_endpoint_target(target, *, locations: bool) -> dict:
    return {
        "id": target.id,
        "uri": str(target),
        "location_type": target.location_type if locations else None,
        "tags": [tag.name for tag in target.tags.all()],
    }


def export_endpoint_entries(finding: Finding, status: serializers.Serializer, *, locations: bool) -> list[dict]:
    entries = []
    for row in finding.locations.all() if locations else finding.status_finding.all():
        target = row.location if locations else row.endpoint
        entries.append({**export_endpoint_target(target, locations=locations), "status": status.to_representation(row)})
    return entries


def export_meta(rows) -> list[dict]:
    return [{"name": meta.name, "value": meta.value} for meta in rows]


def export_product_endpoint(row, product_id: int, *, locations: bool) -> dict:
    """An Endpoint, or a LocationProductReference with its location and the location's metadata prefetched."""
    if not locations:
        return {
            **export_endpoint_target(row, locations=False),
            "status": None,
            "relationship": None,
            "relationship_data": None,
            "meta": export_meta(row.endpoint_meta.all()),
            "location_meta": [],
        }
    metadata = row.location.location_meta.all()
    return {
        **export_endpoint_target(row.location, locations=True),
        "status": row.status,
        "relationship": row.relationship,
        "relationship_data": row.relationship_data,
        "meta": export_meta(meta for meta in metadata if meta.location_product_id == product_id),
        "location_meta": export_meta(meta for meta in metadata if meta.location_product_id is None),
    }


class ExportFilesMixin(serializers.Serializer):
    files = serializers.SerializerMethodField()

    budget = None

    def to_representation(self, obj):
        self.budget = InlineBudget()
        return super().to_representation(obj)

    def get_files(self, obj) -> list[dict]:
        budget = self.budget or InlineBudget()
        return [
            export_file(file_upload, self.context["max_file_bytes"], budget)
            for file_upload in sorted(obj.files.all(), key=lambda file_upload: file_upload.id)
        ]


class ExportProductSerializer(ProductSerializer):
    findings_count = None
    findings_list = None
    prod_type = ProductTypeSerializer(read_only=True)


class ExportCheckListSerializer(serializers.ModelSerializer):
    class Meta:
        model = Check_List
        fields = (
            "id", "session_management", "encryption_crypto", "configuration_management", "authentication",
            "authorization_and_access_control", "data_input_sanitization_validation", "sensitive_data", "other",
            *CHECK_LIST_ISSUE_FIELDS,
        )
        read_only_fields = fields


class ExportGithubConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = GITHUB_Conf
        fields = ("id", "configuration_name")
        read_only_fields = fields


class ExportGithubProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = GITHUB_PKey
        fields = ("id", "git_project", "git_conf", "git_push_notes")
        read_only_fields = fields


class ExportSonarqubeIssueSerializer(serializers.ModelSerializer):
    transitions = serializers.SerializerMethodField()

    class Meta:
        model = Sonarqube_Issue
        fields = ("key", "status", "type", "transitions")
        read_only_fields = fields

    def get_transitions(self, obj) -> list[dict]:
        return [
            {
                "created": render_datetime(row.created),
                "finding_status": row.finding_status,
                "sonarqube_status": row.sonarqube_status,
                "transitions": row.transitions,
            }
            for row in sorted(obj.sonarqube_issue_transition_set.all(), key=attrgetter("id"))
        ]


class ExportJiraInstanceSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Instance
        fields = (
            "id", "configuration_name", "url", "username", "default_issue_type", "issue_template_dir", "epic_name_id",
            "open_status_key", "close_status_key", "info_mapping_severity", "low_mapping_severity",
            "medium_mapping_severity", "high_mapping_severity", "critical_mapping_severity", "finding_text",
            "accepted_mapping_resolution", "false_positive_mapping_resolution", "global_jira_sla_notification",
            "finding_jira_sync",
        )
        read_only_fields = ("id",)


class ExportJiraProjectSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Project
        fields = (
            "id", "project_key", "issue_template_dir", "component", "custom_fields", "close_transition_fields",
            "reopen_transition_fields", "default_assignee", "jira_labels", "add_vulnerability_id_to_jira_label",
            "push_all_issues", "enable_engagement_epic_mapping", "epic_issue_type_name", "push_notes",
            "product_jira_sla_notification", "risk_acceptance_expiration_notification", "enabled", "jira_instance",
            "product", "engagement",
        )
        read_only_fields = ("id",)


class ExportJiraIssueSerializer(serializers.ModelSerializer):
    class Meta:
        model = JIRA_Issue
        fields = (
            "id", "jira_id", "jira_key", "jira_creation", "jira_change", "jira_project", "finding", "engagement",
            "finding_group",
        )
        read_only_fields = fields


def export_jira_row(serializer_class, obj, attribute: str) -> dict | None:
    # A reverse one-to-one with no row raises an AttributeError subclass.
    row = getattr(obj, attribute, None)
    return serializer_class(row).data if row else None


class ExportEngagementSerializer(ExportFilesMixin, EngagementSerializer):
    check_list_detail = serializers.SerializerMethodField()

    def to_representation(self, obj):
        data = super().to_representation(obj)
        if self.context.get("jira"):
            data["jira_project"] = export_jira_row(ExportJiraProjectSerializer, obj, "jira_project")
            data["jira_issue"] = export_jira_row(ExportJiraIssueSerializer, obj, "jira_issue")
        data["threat_model_file"] = export_threat_model(obj, self.context["max_file_bytes"], self.budget)
        return data

    def get_check_list_detail(self, obj) -> dict | None:
        # check_list_prefetch() orders by id, so the first row is the lowest id.
        check_list = next(iter(obj.eng_for_check.all()), None)
        return ExportCheckListSerializer(check_list).data if check_list else None


class ExportTestSerializer(ExportFilesMixin, TestSerializer):
    pass


class ExportFindingSerializer(ExportFilesMixin, FindingSerializer):
    accepted_risks = None
    related_fields = None
    request_response = None
    request_response_pairs = BurpRawRequestResponseMultiSerializer(
        source="burprawrequestresponse_set", many=True, read_only=True,
    )
    risk_acceptances = serializers.PrimaryKeyRelatedField(source="risk_acceptance_set", many=True, read_only=True)

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        # FindingSerializer.__init__ replaces "endpoints" after get_fields, so a declared field would not survive.
        self.fields["endpoints"] = serializers.SerializerMethodField()
        self._locations = locations_enabled()
        self._endpoint_status = LocationFindingReferenceSerializer() if self._locations else EndpointStatusSerializer()

    def get_endpoints(self, obj) -> list[dict]:
        return export_endpoint_entries(obj, self._endpoint_status, locations=self._locations)

    def to_representation(self, obj):
        data = super().to_representation(obj)
        if self.context.get("jira"):
            data["jira_issue"] = export_jira_row(ExportJiraIssueSerializer, obj, "jira_issue")
        if self.context.get("external_issues"):
            issue = getattr(obj, "github_issue", None)
            data["github_issue"] = {"issue_id": issue.issue_id, "issue_url": issue.issue_url} if issue else None
            data["sonarqube_issue"] = (
                ExportSonarqubeIssueSerializer(obj.sonarqube_issue).data if obj.sonarqube_issue_id else None
            )
        return data


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


class ExportTestImportSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test_Import
        fields = (
            "id", "test", "type", "version", "build_id", "commit_hash", "branch_tag", "import_settings", "created", "modified",
        )
        read_only_fields = fields


def audit_event_model(model):
    return apps.get_model("dojo", f"{model.__name__}Event")


def export_value(value):
    if isinstance(value, datetime):
        return render_datetime(value)
    if isinstance(value, FieldFile):
        return value.name
    return value


# One django-pghistory event row. Query it with select_related("pgh_context").
class ExportAuditEventSerializer(serializers.BaseSerializer):
    def __init__(self, model, **kwargs):
        super().__init__(**kwargs)
        self.label = model._meta.label_lower
        self.columns = [
            field.attname for field in audit_event_model(model)._meta.concrete_fields if not field.name.startswith("pgh_")
        ]

    def to_representation(self, event):
        context = event.pgh_context
        return {
            "model": self.label,
            "pgh_id": event.pgh_id,
            "pgh_created_at": render_datetime(event.pgh_created_at),
            "pgh_label": event.pgh_label,
            "pgh_obj_id": event.pgh_obj_id,
            "data": {column: export_value(getattr(event, column)) for column in self.columns},
            "context": None if context is None else {
                "id": context.id,
                "created_at": render_datetime(context.created_at),
                "updated_at": render_datetime(context.updated_at),
                "metadata": context.metadata,
            },
        }


# One django-auditlog entry. Query it with select_related("content_type").
class ExportLegacyAuditEntrySerializer(serializers.BaseSerializer):
    def to_representation(self, entry):
        data = {
            field.attname: export_value(getattr(entry, field.attname))
            for field in LogEntry._meta.concrete_fields
            if field.name != "content_type"
        }
        data["content_type"] = f"{entry.content_type.app_label}.{entry.content_type.model}"
        return data


class ExportToolConfigurationSerializer(ToolConfigurationSerializer):
    class Meta:
        model = Tool_Configuration
        exclude = ("extras",)
        extra_kwargs = ToolConfigurationSerializer.Meta.extra_kwargs


class ExportEngagementPresetSerializer(serializers.ModelSerializer):
    test_type = serializers.SlugRelatedField(slug_field="name", many=True, read_only=True)
    network_locations = serializers.SlugRelatedField(slug_field="location", many=True, read_only=True)

    class Meta:
        model = Engagement_Presets
        exclude = ("product", "archived_at", "archive_batch")


class ExportAPIScanConfigurationSerializer(serializers.ModelSerializer):
    class Meta:
        model = Product_API_Scan_Configuration
        exclude = ("product", "archived_at", "archive_batch")


class ExportContactSerializer(serializers.ModelSerializer):
    class Meta:
        model = Contact
        fields = ("id", "name", "email", "team", "is_admin", "is_globally_read_only")
        read_only_fields = fields


class ExportReportTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Report_Type
        fields = ("id", "name")
        read_only_fields = fields


class ExportTestTypeSerializer(serializers.ModelSerializer):
    class Meta:
        model = Test_Type
        fields = ("id", "name", "static_tool", "dynamic_tool", "active", "dynamically_generated")
        read_only_fields = fields


class ExportAnnouncementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Announcement
        fields = ("message", "style", "dismissable")
        read_only_fields = fields


class ExportLoginBannerSerializer(serializers.ModelSerializer):
    class Meta:
        model = BannerConf
        fields = ("banner_enable", "banner_message")
        read_only_fields = fields


class ExportUserContactInfoSerializer(UserContactInfoSerializer):
    user_profile = None


class ExportUserSerializer(UserSerializer):
    configuration_permissions = serializers.SerializerMethodField()
    contact_info = ExportUserContactInfoSerializer(source="usercontactinfo", read_only=True, allow_null=True)

    class Meta(UserSerializer.Meta):
        fields = (
            *UserSerializer.Meta.fields,
            "contact_info",
        )

    def get_configuration_permissions(self, obj) -> list[str]:
        names = self.context.get("configuration_permission_names")
        if names is None:
            names = configuration_permission_names()
        permissions = [*obj.user_permissions.all(), *(p for group in obj.groups.all() for p in group.permissions.all())]
        return sorted({
            name
            for permission in permissions
            if (name := f"{permission.content_type.app_label}.{permission.codename}") in names
        })

    def to_representation(self, instance):
        # Skip UserSerializer.to_representation: it expects configuration_permissions as ids.
        return serializers.ModelSerializer.to_representation(self, instance)


class ExportChoiceSerializer(serializers.ModelSerializer):
    class Meta:
        model = Choice
        fields = ("id", "order", "label")
        read_only_fields = fields


class ExportQuestionSerializer(serializers.BaseSerializer):
    def to_representation(self, question):
        data = {
            "id": question.id,
            "type": "text",
            "order": question.order,
            "optional": question.optional,
            "text": question.text,
        }
        if isinstance(question, ChoiceQuestion):
            choices = sorted(question.choices.all(), key=attrgetter("order", "id"))
            data |= {
                "type": "choice",
                "multichoice": question.multichoice,
                "choices": ExportChoiceSerializer(choices, many=True).data,
            }
        return data


class ExportQuestionnaireSerializer(serializers.ModelSerializer):
    questions = serializers.SerializerMethodField()

    class Meta:
        model = Engagement_Survey
        fields = ("id", "name", "description", "active", "questions")
        read_only_fields = fields

    def get_questions(self, obj) -> list[dict]:
        return ExportQuestionSerializer(sorted(obj.questions.all(), key=attrgetter("order", "id")), many=True).data


def prefetch_questions(questionnaires: list[Engagement_Survey]) -> None:
    prefetch_related_objects(questionnaires, Prefetch("questions", queryset=Question.polymorphic.all()))
    prefetch_related_objects(
        [
            question
            for questionnaire in questionnaires
            for question in questionnaire.questions.all()
            if isinstance(question, ChoiceQuestion)
        ],
        "choices",
    )


class ExportGeneralSurveySerializer(serializers.ModelSerializer):
    class Meta:
        model = General_Survey
        fields = ("id", "survey", "num_responses", "generated", "expiration")
        read_only_fields = fields


class ExportAnswerSerializer(serializers.BaseSerializer):
    def to_representation(self, answer):
        if isinstance(answer, ChoiceAnswer):
            return {
                "question": answer.question_id,
                "type": "choice",
                "choices": sorted(choice.id for choice in answer.answer.all()),
            }
        return {"question": answer.question_id, "type": "text", "text": answer.answer}


class ExportAnsweredSurveySerializer(serializers.ModelSerializer):
    answers = serializers.SerializerMethodField()

    class Meta:
        model = Answered_Survey
        fields = ("id", "engagement", "survey", "assignee", "responder", "completed", "answered_on", "answers")
        read_only_fields = fields

    def get_answers(self, obj) -> list[dict]:
        return ExportAnswerSerializer(sorted(obj.answer_set.all(), key=attrgetter("question_id", "id")), many=True).data


def prefetch_answers(answered_surveys: list[Answered_Survey]) -> None:
    """A caller must run this first: without it ExportAnsweredSurveySerializer raises AttributeError."""
    prefetch_related_objects(answered_surveys, Prefetch("answer_set", queryset=Answer.polymorphic.all()))
    prefetch_related_objects(
        [
            answer
            for answered_survey in answered_surveys
            for answer in answered_survey.answer_set.all()
            if isinstance(answer, ChoiceAnswer)
        ],
        "answer",
    )


class ExportBenchmarkRequirementSerializer(serializers.ModelSerializer):
    class Meta:
        model = Benchmark_Requirement
        fields = ("id", "objective_number", "objective", "references", "level_1", "level_2", "level_3", "enabled")
        read_only_fields = fields


class ExportBenchmarkCategorySerializer(serializers.ModelSerializer):
    requirements = ExportBenchmarkRequirementSerializer(source="benchmark_requirement_set", many=True, read_only=True)

    class Meta:
        model = Benchmark_Category
        fields = ("id", "name", "objective", "references", "enabled", "requirements")
        read_only_fields = fields


class ExportBenchmarkTypeSerializer(serializers.ModelSerializer):
    categories = ExportBenchmarkCategorySerializer(source="benchmark_category_set", many=True, read_only=True)

    class Meta:
        model = Benchmark_Type
        fields = ("id", "name", "version", "benchmark_source", "enabled", "categories")
        read_only_fields = fields


class ExportTrackingFileSerializer(serializers.ModelSerializer):
    review_status = serializers.SlugRelatedField(slug_field="name", read_only=True)
    tags = serializers.SerializerMethodField()

    class Meta:
        model = Objects_Product
        fields = ("id", "name", "path", "folder", "artifact", "review_status", "tags", "created")
        read_only_fields = fields

    def get_tags(self, obj) -> list[str]:
        return [tag.name for tag in obj.tags.all()]


class ExportBenchmarkResultSerializer(serializers.ModelSerializer):
    notes = NoteSerializer(many=True, read_only=True)

    class Meta:
        model = Benchmark_Product
        fields = ("control", "pass_fail", "enabled", "notes")
        read_only_fields = fields
