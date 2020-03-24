import os

from django import forms
from django.conf import settings

from ..base import (
    FilesystemTemplateLoader,
    ReportBuilder,
    ReportBuilderConfigForm,
    TemplateBasedReportBuilderConfigFormMixin,
    TemplateBasedReportBuilderMixin,
    build_template_context,
    store_finding_image,
)


class FilesystemHTMLTemplateLoader(FilesystemTemplateLoader):
    def is_valid_template_name(self, filename):
        return filename.lower().endswith(".html")


class HTMLConfigForm(
    TemplateBasedReportBuilderConfigFormMixin, ReportBuilderConfigForm
):
    template_name = "dojo/reportng_builder/html/config_form.html"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["images"] = forms.ChoiceField(
            choices=[
                ("", "No images"),
                *ReportBuilderConfigForm.FINDING_IMAGE_SIZE_CHOICES,
            ],
            required=False,
            label="Include finding images",
        )


class HTMLReportBuilder(TemplateBasedReportBuilderMixin, ReportBuilder):
    config_form = HTMLConfigForm

    default_template_backend_options = {
        "builtins": ["dojo.reportng.builders.html.templatetags.html"],
        "context_processors": [],
        "libraries": {},
        "loaders": [
            (
                "dojo.reportng.builders.html.FilesystemHTMLTemplateLoader",
                [os.path.join(settings.MEDIA_ROOT, "reportng", "html_templates")],
                False,
            )
        ],
    }

    def __init__(self, options):
        options.setdefault("code", "html")
        options.setdefault("name", "HTML")
        super().__init__(options)

    def build(self, report, config, buildroot):
        """HTML generation."""
        # These files (relative to buildroot) will be archived at the end
        outputs = []
        try:
            if config["images"]:
                # Collect finding images.
                imgdirname = "images"
                imgdir = os.path.join(buildroot, imgdirname)
                os.makedirs(imgdir)

                def finding_image_hook(finding, finding_ser, img, img_ser):
                    fname = store_finding_image(imgdir, finding, img, config["images"])
                    img_ser["path"] = os.path.join(imgdirname, fname)

            else:
                finding_image_hook = None

            # Render the chosen template
            template = self.template_backend.get_template(config["template"])
            context = build_template_context(
                report, finding_image_hook=finding_image_hook
            )
            context["title"] = config["title"]
            context["config"] = config["template_config"]
            html = template.render(context)

            # Store the HTML
            with open(os.path.join(buildroot, "report.html"), "w") as file:
                file.write(html)
                outputs.append("report.html")
                if config["images"]:
                    outputs.append(imgdirname)

        finally:
            report.store_output_files(buildroot, outputs)
