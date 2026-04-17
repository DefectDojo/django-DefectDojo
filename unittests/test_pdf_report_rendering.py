from django.template import engines
from django.utils.timezone import now

from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    User,
)
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestPdfReportTextWrapping(DojoTestCase):

    """
    Tests that PDF report templates render long and pre-wrapped content
    within margins instead of overflowing.
    """

    fixtures = ["dojo_testdata.json"]

    LONG_URL = "https://app.example.com/assets/vendor-" + "a1b2c3d4" * 8 + ".js.map"

    # Content with an embedded <pre> tag, simulating imports (e.g. BugCrowd CSV)
    # that store HTML-wrapped text in finding fields.
    DESCRIPTION_WITH_PRE = (
        "<pre>\n"
        "An internal debug configuration file (debug-config-e7f3a901.json) is publicly "
        "accessible at the URL: " + LONG_URL + ". "
        "Debug configuration files can reveal internal service addresses, feature flags, "
        "and environment variables. Exposing such files can leak sensitive information "
        "about the application infrastructure, aiding attackers in lateral movement and "
        "facilitating exploitation of internal services.\n"
        "</pre>"
    )

    MITIGATION_WITH_PRE = (
        '<pre data-language="plain">\n'
        "Remove Debug Files From Public Directories: Ensure .json debug configuration "
        "files are not deployed to publicly accessible paths on the web server.\n"
        "Restrict Access: If debug configurations are required in staging environments, "
        "restrict access to authenticated admin users only via IP whitelisting.\n"
        "Environment-Specific Builds: Use separate build profiles for development and "
        "production to ensure debug artifacts are excluded from release bundles.\n"
        "Audit Build Artifacts: Regularly scan deployment artifacts for unintended "
        "inclusion of debug or configuration files.\n"
        "</pre>"
    )

    IMPACT_WITH_PRE = (
        '<pre data-language="plain">\n'
        "Information Disclosure: Attackers can discover internal microservice endpoints, "
        "feature flag states, and environment-specific configuration values.\n"
        "Lateral Movement: Revealed internal addresses may allow attackers to probe "
        "backend services that are not intended to be publicly reachable.\n"
        "Credential Exposure: If the debug configuration includes API keys or tokens "
        "left by developers, this could lead to unauthorized access.\n"
        "</pre>"
    )

    STEPS_WITH_PRE = (
        '<pre data-language="plain">\n'
        "Open a web browser.\n"
        "Navigate to the URL: " + LONG_URL + ".\n"
        "Observe that the configuration file is accessible and can be downloaded.\n"
        "Review the file contents for internal service addresses and environment variables.\n"
        "</pre>"
    )

    # Plain markdown content (no embedded <pre> tags) with a very long unbroken token
    DESCRIPTION_LONG_TOKEN = (
        "A session token was observed in the query string: "
        "token=" + "x" * 300 + " "
        "which exceeds normal length and may cause rendering issues in reports."
    )

    def setUp(self):
        super().setUp()
        self.user = User.objects.get(username="admin")
        self.product_type = Product_Type.objects.create(name="Report Test PT")
        self.product = Product.objects.create(
            name="Report Test Product",
            description="Product for report tests",
            prod_type=self.product_type,
        )
        self.engagement = Engagement.objects.create(
            name="Report Test Engagement",
            product=self.product,
            target_start=now(),
            target_end=now(),
        )
        self.test_type = Test_Type.objects.create(name="Report Test Scan")
        self.test_obj = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            title="Report Rendering Test",
            target_start=now(),
            target_end=now(),
        )
        self.django_engine = engines["django"]

    def _create_finding(self, **kwargs):
        defaults = {
            "title": "Debug Configuration File Exposed",
            "test": self.test_obj,
            "severity": "Medium",
            "description": self.DESCRIPTION_WITH_PRE,
            "mitigation": self.MITIGATION_WITH_PRE,
            "impact": self.IMPACT_WITH_PRE,
            "steps_to_reproduce": self.STEPS_WITH_PRE,
            "active": True,
            "verified": True,
            "reporter": self.user,
            "numerical_severity": "S2",
            "date": now().date(),
        }
        defaults.update(kwargs)
        return Finding.objects.create(**defaults)

    def _render_finding_report(self, findings):
        """Render finding_pdf_report.html with the given findings and return HTML."""
        template = self.django_engine.get_template("dojo/finding_pdf_report.html")
        context = {
            "report_name": "Finding Report",
            "findings": findings,
            "include_finding_notes": 0,
            "include_finding_images": 0,
            "include_executive_summary": 0,
            "include_table_of_contents": 0,
            "include_disclaimer": 0,
            "disclaimer": "",
            "user": self.user,
            "team_name": "Test Team",
            "title": "Finding Report",
            "host": "http://localhost:8080",
            "user_id": self.user.id,
        }
        return template.render(context)

    def test_no_nested_pre_tags_in_report(self):
        """
        Markdown-rendered fields should not produce nested <pre><pre> elements.

        When imported data already contains <pre> tags (common with BugCrowd CSV
        imports), the template wrapper must not add an additional <pre> layer.
        The outer wrapper should be a <div class="report-field">.
        """
        finding = self._create_finding()
        html = self._render_finding_report(Finding.objects.filter(pk=finding.pk))

        # The template should wrap markdown-rendered fields in div.report-field,
        # not in <pre> tags. We should not see <pre><pre> nesting.
        self.assertNotIn("<pre><pre>", html)
        self.assertNotIn("<pre><pre ", html)

        # The report-field wrapper should be present
        self.assertIn('class="report-field"', html)

    def test_report_field_contains_rendered_content(self):
        """Verify that finding content is actually rendered inside report-field divs."""
        finding = self._create_finding()
        html = self._render_finding_report(Finding.objects.filter(pk=finding.pk))

        # The description text should appear in the rendered output
        self.assertIn("debug-config-e7f3a901.json", html)
        self.assertIn("Debug configuration files can reveal", html)

        # Mitigation content should appear
        self.assertIn("Remove Debug Files From Public Directories", html)

    def test_long_unbroken_string_in_report_field(self):
        """
        Fields with very long unbroken strings should render inside report-field
        divs that have overflow-wrap: break-word styling.
        """
        finding = self._create_finding(description=self.DESCRIPTION_LONG_TOKEN)
        html = self._render_finding_report(Finding.objects.filter(pk=finding.pk))

        # The long token should be present in the output
        self.assertIn("x" * 300, html)

        # It should be inside a report-field div, not a bare <pre>
        # Find the section containing our long token
        idx = html.index("x" * 300)
        # Walk backwards to find the nearest opening tag
        preceding = html[max(0, idx - 500):idx]
        self.assertIn("report-field", preceding)

    def test_report_base_css_has_overflow_wrap(self):
        """The report base template must include overflow-wrap for text wrapping."""
        template = self.django_engine.get_template("report_base.html")
        source = template.template.source

        self.assertIn("overflow-wrap: break-word", source)

    def test_report_base_css_styles_nested_pre(self):
        """
        The report base CSS must style .report-field pre to prevent
        nested <pre> elements from breaking out of margins.
        """
        template = self.django_engine.get_template("report_base.html")
        source = template.template.source

        self.assertIn(".report-field pre", source)
        self.assertIn("overflow-wrap: break-word", source)

    def test_raw_request_pre_tags_preserved(self):
        """
        Raw request/response <pre> tags should remain unchanged.

        Only markdown-rendered fields should use div.report-field wrappers.
        The raw_request class pre tags are for literal request/response data
        and should stay as <pre>.
        """
        template = self.django_engine.get_template("dojo/finding_pdf_report.html")
        source = template.template.source
        self.assertIn('class="raw_request"', source)
        # raw_request should still be inside <pre> tags
        self.assertIn('<pre class="raw_request">', source)
