import os
import subprocess

from django import forms
from django.conf import settings

from ..base import (
    FilesystemTemplateLoader,
    ReportBuilder,
    ReportBuilderConfigForm,
    ReportGenerationError,
    TemplateBasedReportBuilderConfigFormMixin,
    TemplateBasedReportBuilderMixin,
    build_template_context,
    store_finding_image,
)


class FilesystemTeXTemplateLoader(FilesystemTemplateLoader):
    def is_valid_template_name(self, filename):
        return filename.lower().endswith(".tex")


class TeXConfigForm(TemplateBasedReportBuilderConfigFormMixin, ReportBuilderConfigForm):
    template_name = "dojo/reportng_builder/tex/config_form.html"

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)

        self.fields["format"] = forms.ChoiceField(choices=self.builder.format_choices)

        self.fields["images"] = forms.ChoiceField(
            choices=[
                ("", "No images"),
                *ReportBuilderConfigForm.FINDING_IMAGE_SIZE_CHOICES,
            ],
            required=False,
            label="Include finding images",
        )


class TeXReportBuilder(TemplateBasedReportBuilderMixin, ReportBuilder):
    config_form = TeXConfigForm

    default_formats = ("src",)
    default_pdf_cmd = (
        "lualatex --interaction=batchmode --output-directory . --output-format pdf "
        "--safer --nosocket --no-shell-escape report.tex"
    )
    default_template_backend_options = {
        "autoescape": False,
        "builtins": ["dojo.reportng.builders.tex.templatetags.tex"],
        "context_processors": [],
        "libraries": {},
        "loaders": [
            (
                "dojo.reportng.builders.tex.FilesystemTeXTemplateLoader",
                [os.path.join(settings.MEDIA_ROOT, "reportng", "tex_templates")],
                False,
            )
        ],
    }

    def __init__(self, options):
        options.setdefault("code", "tex")
        options.setdefault("name", "TeX")
        formats = options.pop("formats", self.default_formats)
        self.pdf_cmd = options.pop("pdf_cmd", self.default_pdf_cmd)

        super().__init__(options)

        self.format_choices = []
        for format in formats:
            if format == "src":
                self.format_choices.append(("src", "TeX source code only"))
            elif format == "pdf":
                self.format_choices.append(("pdf", "Compiled PDF only"))
            elif format == "src_pdf":
                self.format_choices.append(
                    ("src_pdf", "TeX source code + compiled PDF")
                )

    def build(self, report, config, buildroot):
        """TeX source generation and, optionally, compilation."""
        # These files (relative to buildroot) will be archived at the end
        outputs = []
        format = config["format"]
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
            tex_src = template.render(context)

            # Store the source code
            with open(os.path.join(buildroot, "report.tex"), "w") as file:
                file.write(tex_src)
            if format in ("src", "src_pdf"):
                outputs.append("report.tex")
                if config["images"]:
                    outputs.append(imgdirname)

            if format in ("pdf", "src_pdf"):
                # compile
                with open(os.path.join(buildroot, "stderr.log"), "wb") as stderrfile:
                    process = subprocess.Popen(
                        self.pdf_cmd, cwd=buildroot, shell=True, stderr=stderrfile
                    )
                    if process.wait() != 0 or not os.path.isfile(
                        os.path.join(buildroot, "report.pdf")
                    ):
                        outputs.append("stderr.log")
                        if os.path.isfile(os.path.join(buildroot, "report.log")):
                            outputs.append("report.log")
                        raise ReportGenerationError(
                            "PDF compilation failed. Download the generated "
                            "archive and see the contained log files for details."
                        )
                outputs.append("report.pdf")

        finally:
            report.store_output_files(buildroot, outputs)
