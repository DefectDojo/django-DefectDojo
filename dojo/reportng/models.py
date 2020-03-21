import os
from uuid import uuid4
import zipfile

from django.db import models
from django.dispatch import receiver
from django.urls import reverse
from django.utils import timezone
from django.utils.functional import cached_property
from django.utils.text import slugify
from django_msgpackfield import MsgPackField
import rules

from ..models_base import DojoModel, DojoQuerySet, Q, UniqueUploadNameProvider, User
from .builders import BUILDER_REGISTRY


@rules.predicate
def is_report_requester(user, report):
    """Checks whether the user is the requester of the report."""
    return report.requester == user


class ReportNG(DojoModel):
    """
    A ReportNG object, independent of the builder implementation.
    """

    STATUS_DRAFT = 0
    STATUS_REQUESTED = 1
    STATUS_BUILDING = 2
    STATUS_READY = 3
    STATUS_FAILED = 4
    STATUS_DOWNLOADED = 5
    STATUS_CHOICES = (
        (STATUS_DRAFT, "Draft"),
        (STATUS_REQUESTED, "Requested"),
        (STATUS_BUILDING, "Building"),
        (STATUS_READY, "Ready"),
        (STATUS_FAILED, "Failed"),
        (STATUS_DOWNLOADED, "Downloaded"),
    )

    @DojoQuerySet.manager_with_for_user
    def objects(base, user):
        """Only show reports with all products accessible. Drafts are private."""
        if user.is_staff:
            return Q()
        from dojo.models import Product

        return ~Q(products__in=Product.objects.for_user(user).complement()) & (
            ~Q(status=ReportNG.STATUS_DRAFT) | Q(requester=user)
        )

    title = models.CharField(max_length=200)
    content_criteria = MsgPackField()
    builder_code = models.CharField(max_length=20)
    builder_config = MsgPackField()
    requester = models.ForeignKey(User, on_delete=models.CASCADE)
    created = models.DateTimeField(auto_now_add=True)
    done = models.DateTimeField(null=True)

    status = models.IntegerField(choices=STATUS_CHOICES)
    error_message = models.TextField(blank=True)
    task_id = models.CharField(max_length=50, null=True)
    file = models.FileField(
        upload_to=UniqueUploadNameProvider("reportng/%Y/%m/%d", keep_basename=True),
        verbose_name="Report File",
        null=True,
    )

    # Items associated with the report
    products = models.ManyToManyField("Product")
    engagements = models.ManyToManyField("Engagement")
    tests = models.ManyToManyField("Test")
    findings = models.ManyToManyField("Finding")

    def __str__(self):
        return self.title

    def get_absolute_url(self):
        return reverse("reportng_detail", kwargs={"pk": self.pk})

    @cached_property
    def builder(self):
        """Returns the builder instance this report belongs to."""
        return BUILDER_REGISTRY[self.builder_code]

    @property
    def is_downloadable(self):
        """Returns whether this report is ready for download."""
        return (
            self.status
            in (self.STATUS_READY, self.STATUS_DOWNLOADED, self.STATUS_FAILED)
            and self.file
        )

    def store_output_files(self, buildroot, files):
        """Archives the output file(s) of this report."""
        if not files:
            return

        if len(files) == 1 and os.path.isfile(os.path.join(buildroot, files[0])):
            # Easy, just output the single file directly
            outfile_path = os.path.join(buildroot, files[0])
        else:
            # Collect outputs into ZIP archive
            outfile_path = os.path.join(buildroot, "{}.zip".format(uuid4()))
            self.zip_outputs(outfile_path, buildroot, files)

        if self.file:
            self.file.delete()
        created = self.created.strftime("%Y-%m-%d_%H-%M-%S")
        ext = os.path.splitext(outfile_path)[1]
        fname = "report_%s_%s%s" % (slugify(self.title), created, ext)
        with open(outfile_path, "rb") as file:
            self.file.save(fname, file)

    def notify_failure(self, err):
        self.status = self.STATUS_FAILED
        self.error_message = str(err)
        self.done = timezone.now()
        self.save()

        # TODO: avoid these circular import dependencies at all
        # by making create_notification() a method of Alert's model manager.
        from dojo.utils import create_notification

        create_notification(
            event="other",
            source="ReportNG",
            title="Report Generation Failed",
            description=(
                "The generation of report {!r} has failed. Please check the "
                "log for more information. The error was: {!r}".format(self.title, err)
            ),
            url=self.get_absolute_url(),
            icon="bullseye",
        )

    def notify_success(self):
        self.status = self.STATUS_READY
        self.done = timezone.now()
        self.save()

        from dojo.utils import create_notification

        create_notification(
            event="other",
            source="ReportNG",
            title="Report Created",
            description="The report {!r} is ready.".format(self.title),
            url=self.get_absolute_url(),
        )

    @staticmethod
    def zip_outputs(outfile, root, relpaths, mode="w"):
        """Collects items in relpaths (relative to root) into ZIP file outfile.

        The output file is opened using zipfile.ZipFile() with given mode.
        """
        with zipfile.ZipFile(
            outfile, mode, compression=zipfile.ZIP_STORED, allowZip64=True
        ) as zip:
            for relpath in relpaths:
                abspath = os.path.join(root, relpath)
                if os.path.isfile(abspath):
                    zip.write(abspath, relpath)
                elif os.path.isdir(abspath):
                    for _root, dirnames, filenames in os.walk(abspath):
                        for filename in filenames:
                            _abspath = os.path.join(_root, filename)
                            _relpath = os.path.relpath(_abspath, root)
                            zip.write(_abspath, _relpath)

    class Meta:
        verbose_name = "report"
        ordering = ["-created"]
        rules_permissions = {
            "add": rules.is_authenticated,
            "change": rules.is_staff | rules.is_authenticated & is_report_requester,
        }


@receiver(models.signals.post_delete, sender=ReportNG)
def report_deleted(sender, instance, **kwargs):
    """Delete a report's file after report was deleted."""
    if instance.file:
        instance.file.delete(False)
