import logging
import os
import shutil
import tempfile

from celery import shared_task
from django import forms
from django.conf import settings
from django.core.exceptions import ImproperlyConfigured
from django.template import TemplateDoesNotExist, TemplateSyntaxError
from django.template.backends.django import DjangoTemplates
from django.template.loaders.filesystem import Loader as DjangoFilesystemLoader
from django.utils.module_loading import import_string
import yaml

from ...api_v2 import serializers
from ...utils import dict2querydict
from ..models import ReportNG
from . import BUILDER_REGISTRY


class ReportBuilderConfigForm(forms.Form):
    """
    Base for report builder config forms adding common fields.
    """

    # This should be overwritten by the concrete implementation.
    template_name = "path/to/form_template.html"

    title = forms.CharField(max_length=200, required=True, label="Title")

    # Valid values to pass to store_finding_image() as size
    FINDING_IMAGE_SIZE_CHOICES = (
        ("o", "Original size"),
        ("t", "Thumbnails"),
        ("s", "Small"),
        ("m", "Medium"),
        ("l", "Large"),
    )

    def __init__(self, builder, user, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.builder = builder
        self.user = user


class ReportBuilder:
    """
    Base class to derive report builders from.
    """

    # This should be overwritten by the concrete implementation.
    config_form = ReportBuilderConfigForm

    def __init__(self, options):
        """Note: The options dictionary is altered by this method."""
        self.code = options.pop("code")
        self.name = options.pop("name", self.code)
        # Whether to run the build process as a celery task
        self.run_async = options.pop("run_async", False)

        if options:
            raise ImproperlyConfigured(
                "These settings were not understood by %s: %r"
                % (self.__class__.__name__, options)
            )

    def _get_buildroot(self, report):
        """Creates a tempfile.TemporaryDirectory instance to be used as build root."""
        return tempfile.TemporaryDirectory(prefix="dd-reportng-{}-".format(report.pk))

    def build(self, report, config, buildroot):
        """Should do the real building.

        report is the ReportNG object.
        config is an instance of the ReportBuilderConfigForm, ensured to be valid.
        buildroot is the path of a writable temporary directory.

        This method is either called synchronously or from a celery task.
        In case of a build failure, ReportGenerationError should be raised.
        """
        raise NotImplementedError("to be overwritten by a builder implementation")

    def call_build(self, report):
        """invokes self.build() and takes care of things like exception handling."""
        config_form = self.get_config_form(
            report.requester, data=dict2querydict(report.builder_config)
        )
        try:
            # We can assert this here because the data was validated before saving
            assert config_form.is_valid(), "config form validation failed"
            with self._get_buildroot(report) as buildroot:
                self.build(report, config_form.cleaned_data, buildroot)
        except Exception as err:
            try:
                self.reraise_exception(err)
            except Exception as reraised_err:
                report.notify_failure(err)
                if settings.DEBUG or not isinstance(err, ReportGenerationError):
                    # Re-raise to catch admin's attention as this is unexpected
                    raise reraised_err from err
        else:
            report.notify_success()

    def dispatch(self, report):
        """Dispatches the report generation.

        This method is called by the BuilderView and triggers the
        generation of a report, either synchronous or asynchronous,
        depending on the builder implementation.
        """
        report.status = ReportNG.STATUS_BUILDING
        report.task_id = None
        report.save()
        if self.run_async:
            async_build_report.delay(report.pk)
        else:
            self.call_build(report)

    def get_config_form(self, user, *args, **kwargs):
        """Returns a new instance of the builder's config form

        All positional and keyword arguments are passed through.
        """
        return self.config_form(self, user, *args, **kwargs)

    def reraise_exception(self, err):
        """Hook for rewriting exceptions raised during report building."""
        raise err


class TemplateBasedReportBuilderConfigFormMixin:
    """
    Mixin for the config form implementations used with TemplateBasedReportBuilderMixin.

    It adds template selection and YAML config loading fields.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        loaders = self.builder.template_backend.engine.template_loaders
        self.fields["template"] = forms.ChoiceField(
            choices=[
                (name, name)
                for loader in loaders
                for name in loader.get_template_names(self.user)
            ]
        )
        self.fields["template_config"] = YAMLField(
            max_length=100 * 1024 ** 2,  # 100 KiB
            required=False,
            label="Custom configuration for the template (in YAML syntax)",
        )
        self.fields["load_default_template_config"] = forms.BooleanField(
            required=False, widget=forms.HiddenInput()
        )

        # If requested, load the default config for a template
        prefixed_key = lambda key: "%s-%s" % (self.prefix, key) if self.prefix else key
        if self.is_bound and self["load_default_template_config"].data:
            self.data.pop(prefixed_key("template_config"), None)
            self.is_valid()
            self.data[
                prefixed_key("template_config")
            ] = self.builder.template_backend.get_template_config(
                self.cleaned_data.get("template", "")
            )


class TemplateBasedReportBuilderMixin:
    """
    Mixin for ReportBuilder implementations that work on a template.
    The initialized template backend will be available as self.template_backend and
    can be used in build().
    """

    # Overwrite these attributes in the concrete builder implementation
    default_template_backend = "dojo.reportng.builders.base.SaferDjangoTemplates"
    default_template_backend_options = {
        "builtins": [],
        "context_processors": [],
        "libraries": {},
        "loaders": [],
    }

    def __init__(self, options):
        options.setdefault("run_async", True)
        backend = options.pop("template_backend", self.default_template_backend)
        backend_options = options.pop(
            "template_backend_options", self.default_template_backend_options
        )

        super().__init__(options)

        self.template_backend = import_string(backend)(
            {
                "NAME": "reportng_%s" % self.code,
                "DIRS": [],
                "APP_DIRS": False,
                "OPTIONS": backend_options,
            }
        )

    def reraise_exception(self, err):
        """Calls TemplateBackendMixin.reraise_exception() on a build error."""
        self.template_backend.reraise_exception(err)


class ReportGenerationError(Exception):
    """
    An exception to be used for signalling failures during report generation.
    """


class TemplateBackendMixin:
    """
    Mixin declaring methods common to all compatible template backend implementations.
    """

    def get_template_config(self, template_name):
        """Returns the YAML of the default config for given template."""
        return self.get_template("%s.config" % template_name).render({})

    def reraise_exception(self, err):
        """Hook for rewriting exceptions raised during template handling."""
        raise err


class SaferDjangoTemplates(TemplateBackendMixin, DjangoTemplates):
    """
    A subclass of the original DjangoTemplates backend which disables
    loading of templatetag libraries from installed apps. All libraries
    which should be available must be configured via the "libraries"
    option when initializing the backend.
    """

    def get_template_config(self, template_name):
        """Catches errors while loading the default config."""
        try:
            return super().get_template_config(template_name)
        except TemplateDoesNotExist:
            return "# No default configuration provided for this template."
        except Exception as err:
            return "# Error loading the default configuration: %r" % err

    def get_templatetag_libraries(self, custom_libraries):
        """Return only the supplied custom_libraries argument."""
        return custom_libraries

    def reraise_exception(self, err):
        """Maps TemplateSyntaxError to ReportGenerationError with line number."""
        if isinstance(err, TemplateSyntaxError) and hasattr(err, "template_debug"):
            dbg = err.template_debug
            raise ReportGenerationError(
                "Template error at %r, line %d: %s"
                % (dbg["name"], dbg["line"], dbg["message"])
            )
        # No debug info available
        super().reraise_exception(err)


class TemplateLoaderMixin:
    """
    Defines the additional methods template loaders must implement in order to
    support fetching a list of available templates.
    """

    def get_template_names(self, user):
        """Yields the names of all templates available to given user."""
        raise NotImplementedError


class FilesystemTemplateLoader(TemplateLoaderMixin, DjangoFilesystemLoader):
    """
    Template loader fetching templates from one or more directories on the filesystem.
    """

    def __init__(self, engine, dirs, include_subdirectories=False):
        super().__init__(engine, dirs)
        self.include_subdirectories = include_subdirectories

        # Try to create the directories
        for path in dirs:
            try:
                os.makedirs(path)
            except FileExistsError:
                pass
            except OSError as err:
                logging.warning(
                    "Couldn't create directory for report templates %r: %r", path, err
                )

    def get_template_names(self, user):
        for directory in self.get_dirs():
            for root, dirnames, filenames in os.walk(directory):
                for filename in filenames:
                    if self.is_valid_template_name(filename):
                        yield os.path.relpath(os.path.join(root, filename), directory)
                if not self.include_subdirectories:
                    # Don't recurse into subdirectories
                    break

    def is_valid_template_name(self, filename):
        raise NotImplementedError


class YAMLField(forms.CharField):
    """
    A form field whose input is deserialized from YAML.
    """

    def __init__(self, *args, **kwargs):
        if "widget" not in kwargs:
            kwargs["widget"] = forms.Textarea()
        super().__init__(*args, **kwargs)

    def to_python(self, value):
        """Deserializes the YAML."""
        value = super().to_python(value)
        try:
            return yaml.load(value, Loader=yaml.SafeLoader)
        except yaml.YAMLError as err:
            raise forms.ValidationError("Invalid YAML: %s" % err, code="invalid-yaml")


@shared_task(bind=True, name="dojo.tasks.async_build_report")
def async_build_report(self, report_pk):
    """Celery task for building reports asynchronously."""
    report = None
    try:
        report = ReportNG.objects.get(pk=report_pk)
        report.status = ReportNG.STATUS_BUILDING
        report.task_id = self.request.id
        report.save()
        builder = BUILDER_REGISTRY[report.builder_code]
    except Exception as err:
        if report is not None:
            report.notify_failure(err)
        # Re-raise to catch admin's attention as this is unexpected
        raise
    else:
        builder.call_build(report)

    return True


def build_template_context(report, finding_image_hook=None):
    """Turns the ORM objects into a nested, serializable datastructure.

    finding_image_hook, if set, is called for each finding image with these arguments:
    - finding
    - serialized finding
    - image
    - serialized image
    """
    _serialize = lambda obj, serializer: serializer().to_representation(obj)
    ctx = {}
    products = ctx["products"] = []
    for product in report.products.all():
        _product = _serialize(product, serializers.ProductSerializer)
        products.append(_product)

        engs = _product["engagements"] = []
        for eng in filter(lambda e: e.product == product, report.engagements.all()):
            _eng = _serialize(eng, serializers.EngagementSerializer)
            engs.append(_eng)

            tests = _eng["tests"] = []
            for test in filter(lambda t: t.engagement == eng, report.tests.all()):
                _test = _serialize(test, serializers.TestSerializer)
                tests.append(_test)

                findings = _test["findings"] = []
                for finding in filter(lambda f: f.test == test, report.findings.all()):
                    _finding = _serialize(finding, serializers.FindingSerializer)
                    if finding_image_hook is not None:
                        images = dict(
                            map(lambda img: (img.pk, img), finding.images.all())
                        )
                        for _img in _finding["images"]:
                            finding_image_hook(
                                finding, _finding, images[_img["id"]], _img
                            )
                    findings.append(_finding)

    return ctx


def store_finding_image(outdir, finding, image, size):
    """Stores a finding image into given directory.

    size must be a valid choice from ReportBuilderConfigForm.FINDING_IMAGE_SIZE_CHOICES.
    The name of the newly created file is returned.
    """
    size_attr = {
        "o": "image",
        "t": "image_thumbnail",
        "s": "image_small",
        "m": "image_medium",
        "l": "image_large",
    }[size]
    img = getattr(image, size_attr)
    ext = os.path.splitext(img.name)[1]
    imgfilename = "f{}-i{}-{}{}".format(finding.pk, image.pk, size, ext)
    with open(os.path.join(outdir, imgfilename), "wb") as file:
        shutil.copyfileobj(img, file)
    return imgfilename
