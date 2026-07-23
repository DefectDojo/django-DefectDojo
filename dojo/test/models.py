import logging
from contextlib import suppress

from django.conf import settings
from django.contrib.postgres.indexes import GinIndex
from django.contrib.postgres.search import SearchVector
from django.db import models
from django.db.models import Count, Q
from django.urls import reverse
from django.utils.translation import gettext as _
from django_extensions.db.models import TimeStampedModel
from tagulous.models import TagField

logger = logging.getLogger(__name__)
deduplicationLogger = logging.getLogger("dojo.specific-loggers.deduplication")

IMPORT_CREATED_FINDING = "N"
IMPORT_CLOSED_FINDING = "C"
IMPORT_REACTIVATED_FINDING = "R"
IMPORT_UNTOUCHED_FINDING = "U"

IMPORT_ACTIONS = [
    (IMPORT_CREATED_FINDING, "created"),
    (IMPORT_CLOSED_FINDING, "closed"),
    (IMPORT_REACTIVATED_FINDING, "reactivated"),
    (IMPORT_UNTOUCHED_FINDING, "untouched"),
]


class Test_Type(models.Model):
    name = models.CharField(max_length=200, unique=True)
    static_tool = models.BooleanField(default=False)
    dynamic_tool = models.BooleanField(default=False)
    active = models.BooleanField(default=True)
    dynamically_generated = models.BooleanField(
        default=False,
        help_text=_("Set to True for test types that are created at import time"))

    class Meta:
        ordering = ("name",)

    def __str__(self):
        return self.name

    def get_breadcrumbs(self):
        return [{"title": str(self),
               "url": None}]


class Test(models.Model):
    engagement = models.ForeignKey("dojo.Engagement", editable=False, on_delete=models.CASCADE)
    lead = models.ForeignKey("dojo.Dojo_User", editable=True, null=True, blank=True, on_delete=models.RESTRICT)
    test_type = models.ForeignKey("dojo.Test_Type", on_delete=models.CASCADE)
    scan_type = models.TextField(null=True)
    title = models.CharField(max_length=255, null=True, blank=True)
    description = models.TextField(null=True, blank=True)
    target_start = models.DateTimeField()
    target_end = models.DateTimeField()
    percent_complete = models.IntegerField(null=True, blank=True,
                                           editable=True)
    notes = models.ManyToManyField("dojo.Notes", blank=True,
                                   editable=False)
    files = models.ManyToManyField("dojo.FileUpload", blank=True, editable=False)
    environment = models.ForeignKey("dojo.Development_Environment", null=True,
                                    blank=False, on_delete=models.RESTRICT)

    updated = models.DateTimeField(auto_now=True, null=True)
    created = models.DateTimeField(auto_now_add=True, null=True)

    tags = TagField(blank=True, force_lowercase=True, help_text=_("Add tags that help describe this test. Choose from the list or add new tags. Press Enter key to add."))
    inherited_tags = TagField(blank=True, force_lowercase=True, help_text=_("Internal use tags sepcifically for maintaining parity with product. This field will be present as a subset in the tags field"))

    version = models.CharField(max_length=100, null=True, blank=True)

    build_id = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Build ID that was tested, a reimport may update this field."), verbose_name=_("Build ID"))
    commit_hash = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Commit hash tested, a reimport may update this field."), verbose_name=_("Commit Hash"))
    branch_tag = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Tag or branch that was tested, a reimport may update this field."), verbose_name=_("Branch/Tag"))
    api_scan_configuration = models.ForeignKey("dojo.Product_API_Scan_Configuration", null=True, editable=True, blank=True, on_delete=models.CASCADE, verbose_name=_("API Scan Configuration"))

    class Meta:
        indexes = [
            models.Index(fields=["engagement", "test_type"]),
            # Global search (pro/search/): weighted tsvector FTS + trigram fuzzy match.
            GinIndex(
                SearchVector("title", weight="A", config="english")
                + SearchVector("description", weight="B", config="english"),
                name="dojo_test_fts_gin",
            ),
            GinIndex(fields=["title"], opclasses=["gin_trgm_ops"], name="dojo_test_title_trgm"),
        ]

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.unsaved_metadata: list = []

    def __str__(self):
        if self.title:
            return f"{self.title} ({self.test_type})"
        return str(self.test_type)

    def get_absolute_url(self):
        return reverse("view_test", args=[str(self.id)])

    def test_type_name(self) -> str:
        return self.test_type.name

    def get_breadcrumbs(self):
        bc = self.engagement.get_breadcrumbs()
        bc += [{"title": str(self),
                "url": reverse("view_test", args=(self.id,))}]
        return bc

    def copy(self, engagement=None):
        from dojo.models import Finding, copy_model_util  # noqa: PLC0415 -- lazy import, avoids circular dependency  # isort: skip
        copy = copy_model_util(self)
        # Save the necessary ManyToMany relationships
        old_notes = list(self.notes.all())
        old_files = list(self.files.all())
        old_tags = list(self.tags.all())
        old_findings = list(Finding.objects.filter(test=self))
        if engagement:
            copy.engagement = engagement
        # Save the object before setting any ManyToMany relationships
        copy.save()
        # Copy the notes
        for notes in old_notes:
            copy.notes.add(notes.copy())
        # Copy the files
        for files in old_files:
            copy.files.add(files.copy())
        # Copy the Findings
        for finding in old_findings:
            finding.copy(test=copy)
        # Assign any tags
        copy.tags.set(old_tags)

        return copy

    # only used by bulk risk acceptance api
    @property
    def unaccepted_open_findings(self):
        from dojo.models import Finding  # noqa: PLC0415 -- lazy import, avoids circular dependency
        from dojo.utils import get_system_setting  # noqa: PLC0415 circular import
        findings = Finding.objects.filter(risk_accepted=False, active=True, duplicate=False, test=self)
        if get_system_setting("enforce_verified_status", True) or get_system_setting("enforce_verified_status_metrics", True):
            findings = findings.filter(verified=True)

        return findings

    def accept_risks(self, accepted_risks):
        self.engagement.risk_acceptance.add(*accepted_risks)

    @property
    def deduplication_algorithm(self):
        deduplicationAlgorithm = settings.DEDUPE_ALGO_LEGACY

        if hasattr(settings, "DEDUPLICATION_ALGORITHM_PER_PARSER"):
            if (self.test_type.name in settings.DEDUPLICATION_ALGORITHM_PER_PARSER):
                deduplicationLogger.debug(f"using DEDUPLICATION_ALGORITHM_PER_PARSER for test_type.name: {self.test_type.name}")
                deduplicationAlgorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER[self.test_type.name]
            elif (self.scan_type in settings.DEDUPLICATION_ALGORITHM_PER_PARSER):
                deduplicationLogger.debug(f"using DEDUPLICATION_ALGORITHM_PER_PARSER for scan_type: {self.scan_type}")
                deduplicationAlgorithm = settings.DEDUPLICATION_ALGORITHM_PER_PARSER[self.scan_type]
        else:
            deduplicationLogger.debug("Section DEDUPLICATION_ALGORITHM_PER_PARSER not found in settings.dist.py")

        deduplicationLogger.debug(f"DEDUPLICATION_ALGORITHM_PER_PARSER is: {deduplicationAlgorithm}")
        return deduplicationAlgorithm

    @property
    def hash_code_fields(self):
        """Retrieve OS HASH_CODE_FIELDS_PER_SCANNER settings. Be aware when calling this to make sure Pro doesn't use these OS seetings"""
        hashCodeFields = None

        if hasattr(settings, "HASHCODE_FIELDS_PER_SCANNER"):
            if (self.test_type.name in settings.HASHCODE_FIELDS_PER_SCANNER):
                deduplicationLogger.debug(f"using HASHCODE_FIELDS_PER_SCANNER for test_type.name: {self.test_type.name}")
                hashCodeFields = settings.HASHCODE_FIELDS_PER_SCANNER[self.test_type.name]
            elif (self.scan_type in settings.HASHCODE_FIELDS_PER_SCANNER):
                deduplicationLogger.debug(f"using HASHCODE_FIELDS_PER_SCANNER for scan_type: {self.scan_type}")
                hashCodeFields = settings.HASHCODE_FIELDS_PER_SCANNER[self.scan_type]
            else:
                deduplicationLogger.warning(f"test_type name {self.test_type.name} and scan_type {self.scan_type} not found in HASHCODE_FIELDS_PER_SCANNER")
        else:
            deduplicationLogger.debug("Section HASHCODE_FIELDS_PER_SCANNER not found in settings.dist.py")

        hash_code_fields_always = getattr(settings, "HASH_CODE_FIELDS_ALWAYS", [])
        deduplicationLogger.debug(f"HASHCODE_FIELDS_PER_SCANNER is: {hashCodeFields} + HASH_CODE_FIELDS_ALWAYS: {hash_code_fields_always}")

        return hashCodeFields

    @property
    def hash_code_allows_null_cwe(self):
        hashCodeAllowsNullCwe = True

        if hasattr(settings, "HASHCODE_ALLOWS_NULL_CWE"):
            if (self.test_type.name in settings.HASHCODE_ALLOWS_NULL_CWE):
                deduplicationLogger.debug(f"using HASHCODE_ALLOWS_NULL_CWE for test_type.name: {self.test_type.name}")
                hashCodeAllowsNullCwe = settings.HASHCODE_ALLOWS_NULL_CWE[self.test_type.name]
            elif (self.scan_type in settings.HASHCODE_ALLOWS_NULL_CWE):
                deduplicationLogger.debug(f"using HASHCODE_ALLOWS_NULL_CWE for scan_type: {self.scan_type}")
                hashCodeAllowsNullCwe = settings.HASHCODE_ALLOWS_NULL_CWE[self.scan_type]
        else:
            deduplicationLogger.debug("Section HASHCODE_ALLOWS_NULL_CWE not found in settings.dist.py")

        deduplicationLogger.debug(f"HASHCODE_ALLOWS_NULL_CWE is: {hashCodeAllowsNullCwe}")
        return hashCodeAllowsNullCwe

    def delete(self, *args, product_grading_option=True, **kwargs):
        logger.debug("%d test delete", self.id)
        super().delete(*args, **kwargs)
        if product_grading_option:
            from dojo.models import Engagement, Product  # noqa: PLC0415 -- lazy import, avoids circular dependency
            with suppress(Test.DoesNotExist, Engagement.DoesNotExist, Product.DoesNotExist):
                # Suppressing a potential issue created from async delete removing
                # related objects in a separate task
                from dojo.utils import perform_product_grading  # noqa: PLC0415 circular import
                perform_product_grading(self.engagement.product)

    @property
    def statistics(self):
        """Queries the database, no prefetching, so could be slow for lists of model instances"""
        from dojo.models import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            Finding,
            _get_annotations_for_statistics,
            _get_statistics_for_queryset,
        )
        return _get_statistics_for_queryset(Finding.objects.filter(test=self), _get_annotations_for_statistics)


class Test_Import(TimeStampedModel):

    IMPORT_TYPE = "import"
    REIMPORT_TYPE = "reimport"

    test = models.ForeignKey("dojo.Test", editable=False, null=False, blank=False, on_delete=models.CASCADE)
    findings_affected = models.ManyToManyField("dojo.Finding", through="dojo.Test_Import_Finding_Action")
    import_settings = models.JSONField(null=True)
    type = models.CharField(max_length=64, null=False, blank=False, default="unknown")

    version = models.CharField(max_length=100, null=True, blank=True)
    build_id = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Build ID that was tested, a reimport may update this field."), verbose_name=_("Build ID"))
    commit_hash = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Commit hash tested, a reimport may update this field."), verbose_name=_("Commit Hash"))
    branch_tag = models.CharField(editable=True, max_length=150,
                                   null=True, blank=True, help_text=_("Tag or branch that was tested, a reimport may update this field."), verbose_name=_("Branch/Tag"))

    def get_queryset(self):
        logger.debug("prefetch test_import counts")
        super_query = super().get_queryset()
        super_query = super_query.annotate(created_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_CREATED_FINDING)))
        super_query = super_query.annotate(closed_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_CLOSED_FINDING)))
        super_query = super_query.annotate(reactivated_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_REACTIVATED_FINDING)))
        return super_query.annotate(untouched_findings_count=Count("findings", filter=Q(test_import_finding_action__action=IMPORT_UNTOUCHED_FINDING)))

    class Meta:
        ordering = ("-id",)
        indexes = [
            models.Index(fields=["created", "test", "type"]),
        ]

    def __str__(self):
        return self.created.strftime("%Y-%m-%d %H:%M:%S")

    @property
    def statistics(self):
        """Queries the database, no prefetching, so could be slow for lists of model instances"""
        from dojo.models import (  # noqa: PLC0415 -- lazy import, avoids circular dependency
            Finding,
            _get_annotations_for_statistics,
            _get_statistics_for_queryset,
        )
        stats = {}
        for action in IMPORT_ACTIONS:
            stats[action[1].lower()] = _get_statistics_for_queryset(Finding.objects.filter(test_import_finding_action__test_import=self, test_import_finding_action__action=action[0]), _get_annotations_for_statistics)
        return stats


class Test_Import_Finding_Action(TimeStampedModel):
    test_import = models.ForeignKey("dojo.Test_Import", editable=False, null=False, blank=False, on_delete=models.CASCADE)
    finding = models.ForeignKey("dojo.Finding", editable=False, null=False, blank=False, on_delete=models.CASCADE)
    action = models.CharField(max_length=100, null=True, blank=True, choices=IMPORT_ACTIONS)

    class Meta:
        indexes = [
            models.Index(fields=["finding", "action", "test_import"]),
        ]
        unique_together = (("test_import", "finding"))
        ordering = ("test_import", "action", "finding")

    def __str__(self):
        return f"{self.finding.id}: {self.action}"
