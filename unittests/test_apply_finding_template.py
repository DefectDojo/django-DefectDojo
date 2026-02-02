import datetime

from crum import impersonate
from django.conf import settings
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.test.client import RequestFactory
from django.utils import timezone

from dojo.finding import views
from dojo.finding.helper import save_endpoints_template, save_vulnerability_ids_template
from dojo.models import (
    Engagement,
    Finding,
    Finding_Template,
    Notes,
    Product,
    Product_Member,
    Product_Type,
    Role,
    System_Settings,
    Test,
    Test_Type,
    Vulnerability_Id,
)
from dojo.test import views as test_views
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


class FindingMother:

    @staticmethod
    def create():
        settings = System_Settings()
        settings.save()

        p = Product()
        p.name = "Test Product"
        p.description = "Product for Testing Apply Template functionality"
        p.prod_type = Product_Type.objects.get(id=1)
        p.save()

        e = Engagement()
        e.product = p
        e.target_start = timezone.now()
        e.target_end = e.target_start + datetime.timedelta(days=5)
        e.save()

        tt = Test_Type()
        tt.name = "Temporary Test"
        tt.save()

        t = Test()
        t.engagement = e
        t.test_type = tt
        t.target_start = timezone.now()
        t.target_end = t.target_start + datetime.timedelta(days=5)
        t.save()

        user = FindingTemplateTestUtil.create_user(is_staff=True)

        f = Finding()
        f.title = "Finding for Testing Apply Template functionality"
        f.severity = "High"
        f.description = "Finding for Testing Apply Template Functionality"
        f.test = t
        f.reporter = user
        f.last_reviewed = timezone.now()
        f.last_reviewed_by = user
        f.cve = None  # Set explicitly as it's required (blank=False)
        f.save()
        return f


class FindingTemplateMother:
    @staticmethod
    def create():
        tmp = Finding_Template()
        tmp.title = "Finding Template for Testing Apply Template functionality"
        tmp.cwe = 0
        tmp.severity = "Low"
        tmp.description = "Finding Template for Testing Apply Template functionality"
        tmp.mitigation = "Finding Template Mitigation"
        tmp.impact = "Finding Template Impact"
        tmp.save()
        return tmp


class FindingTemplateTestUtil:

    def __init__(self):
        pass

    @staticmethod
    def create_user(is_staff):
        user_count = User.objects.count()
        user = User()
        user.is_staff = is_staff
        user.is_superuser = is_staff  # Superuser has all permissions
        user.username = "TestUser" + str(user_count)
        user.save()
        return user

    @staticmethod
    def create_user_with_role(product, role_name, *, is_staff=False):
        """Create a user with a specific role on a product"""
        user_count = User.objects.count()
        user = User()
        user.is_staff = is_staff
        user.is_superuser = False
        user.username = f"TestUser{role_name}{user_count}"
        user.save()
        role = Role.objects.get(name=role_name)
        Product_Member(user=user, product=product, role=role).save()
        return user

    @staticmethod
    def create_get_request(user, path):
        rf = RequestFactory()
        get_request = rf.get(path)
        get_request.user = user
        get_request.session = {}

        return get_request

    @staticmethod
    def create_post_request(user, path, data):
        rf = RequestFactory()
        post_request = rf.post(path, data=data)
        post_request.user = user
        post_request.session = {}
        messages = FallbackStorage(post_request)
        post_request._messages = messages

        return post_request


@versioned_fixtures
class TestApplyFindingTemplate(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = FindingMother.create()
        self.template = FindingTemplateMother.create()
        self.apply_template_url = f"finding/{self.finding.id}/{self.template.id}/apply_template_to_finding"

    def make_request(self, user_is_staff, finding_id, template_id, data=None):
        user = FindingTemplateTestUtil.create_user(user_is_staff)

        if data:
            request = FindingTemplateTestUtil.create_post_request(user, self.apply_template_url, data)
        else:
            request = FindingTemplateTestUtil.create_get_request(user, self.apply_template_url)

        with impersonate(user):
            return views.apply_template_to_finding(request, fid=finding_id, tid=template_id)

    def test_apply_template_to_finding_with_data_does_not_display_error_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id,
                                   data={"title": "Finding for Testing Apply Template functionality",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertEqual(result.status_code, 302)
        self.assertNotIn("There appears to be errors on the form", str(result))

    def test_apply_template_to_finding_with_data_returns_to_view_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id,
                                   data={"title": "Finding for Testing Apply Template functionality",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertIsNotNone(result)
        self.assertEqual(302, result.status_code)
        self.assertEqual(f"/finding/{self.finding.id}", result.url)

    def test_apply_template_to_finding_with_data_saves_success(self):
        test_title = "Finding for Testing Apply Template functionality"
        test_cwe = 89
        test_severity = "High"
        test_description = "Finding for Testing Apply Template Functionality"
        test_mitigation = "template mitigation"
        test_impact = "template impact"

        self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id,
                                   data={"title": test_title,
                                    "cwe": test_cwe,
                                    "severity": test_severity,
                                    "description": test_description,
                                    "mitigation": test_mitigation,
                                    "impact": test_impact})

        f = Finding.objects.get(id=self.finding.id)
        # Title is automatically title-cased by Finding.save()
        self.assertEqual("Finding for Testing Apply Template Functionality", f.title)
        self.assertEqual(test_cwe, f.cwe)
        self.assertEqual(test_severity, f.severity)
        self.assertEqual(test_description, f.description)
        self.assertEqual(test_mitigation, f.mitigation)
        self.assertEqual(test_impact, f.impact)

    def test_unauthorized_apply_template_to_finding_fails(self):
        """Test that a non-superuser without permissions cannot apply template"""
        with self.assertRaises(PermissionDenied):
            self.make_request(user_is_staff=False, finding_id=self.finding.id, template_id=self.template.id,
                                   data={"title": "Finding for Testing Apply Template functionality",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"},
                                   )

    def test_reader_role_cannot_apply_template(self):
        """Test that a Reader role user (read-only) cannot apply template"""
        reader_user = FindingTemplateTestUtil.create_user_with_role(
            self.finding.test.engagement.product, "Reader", is_staff=False,
        )
        request = FindingTemplateTestUtil.create_post_request(
            reader_user, self.apply_template_url,
            data={"title": "Finding for Testing Apply Template functionality",
                  "cwe": "89",
                  "severity": "High",
                  "description": "Finding for Testing Apply Template Functionality",
                  "mitigation": "template mitigation",
                  "impact": "template impact"},
        )
        with impersonate(reader_user), self.assertRaises(PermissionDenied):
            views.apply_template_to_finding(request, fid=self.finding.id, tid=self.template.id)

    def test_writer_role_can_apply_template(self):
        """Test that a Writer role user (non-staff) can apply template"""
        writer_user = FindingTemplateTestUtil.create_user_with_role(
            self.finding.test.engagement.product, "Writer", is_staff=False,
        )
        request = FindingTemplateTestUtil.create_post_request(
            writer_user, self.apply_template_url,
            data={"title": "Finding for Testing Apply Template functionality",
                  "cwe": "89",
                  "severity": "High",
                  "description": "Finding for Testing Apply Template Functionality",
                  "mitigation": "template mitigation",
                  "impact": "template impact"},
        )
        with impersonate(writer_user):
            result = views.apply_template_to_finding(request, fid=self.finding.id, tid=self.template.id)
            self.assertEqual(302, result.status_code)
            self.assertEqual(f"/finding/{self.finding.id}", result.url)

    def test_apply_template_to_finding_with_illegal_finding_fails(self):
        with self.assertRaises(Http404):
            self.make_request(user_is_staff=True, finding_id=99999, template_id=self.template.id)

    def test_apply_template_to_finding_with_illegal_template_fails(self):
        with self.assertRaises(Http404):
            self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=99999)

    def test_apply_template_to_finding_with_no_data_returns_view_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id, data=None)
        self.assertIsNotNone(result)
        self.assertEqual(302, result.status_code)
        self.assertEqual(f"/finding/{self.finding.id}", result.url)

    def test_apply_template_to_finding_without_required_field_displays_field_title_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id,
                                   data={"title": "",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertContains(result, "The title is required.")

    def test_apply_template_to_finding_without_required_field_displays_error_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id,
                                   data={"title": "",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertContains(result, "There appears to be errors on the form")


@versioned_fixtures
class TestFindTemplateToApply(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = FindingMother.create()
        FindingTemplateMother.create()
        self.choose_template_url = f"finding/{self.finding.id}/find_template_to_apply"

    def make_request(self, user_is_staff, finding_id, data=None):
        user = FindingTemplateTestUtil.create_user(user_is_staff)

        if data:
            request = FindingTemplateTestUtil.create_post_request(user, self.choose_template_url, data)
        else:
            request = FindingTemplateTestUtil.create_get_request(user, self.choose_template_url)

        with impersonate(user):
            return views.find_template_to_apply(request, fid=finding_id)

    def test_unauthorized_find_template_to_apply_fails(self):
        with self.assertRaises(PermissionDenied):
            self.make_request(user_is_staff=False, finding_id=self.finding.id)

    def test_authorized_find_template_to_apply_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id)
        self.assertEqual(200, result.status_code)

    def test_find_template_to_apply_displays_templates_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id)
        self.assertContains(result, "Finding Template for Testing Apply Template functionality")

    def test_find_template_to_apply_displays_breadcrumb(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id)
        self.assertContains(result, "Apply Template to Finding")


@versioned_fixtures
class TestChooseFindingTemplateOptions(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = FindingMother.create()
        self.template = FindingTemplateMother.create()
        self.finding_template_options_url = f"finding/{self.template.id}/{self.finding.id}/choose_finding_template_options"

    def make_request(self, user_is_staff, finding_id, template_id, data=None):
        user = FindingTemplateTestUtil.create_user(user_is_staff)

        if data:
            request = FindingTemplateTestUtil.create_post_request(user, self.finding_template_options_url, data)
        else:
            request = FindingTemplateTestUtil.create_get_request(user, self.finding_template_options_url)

        with impersonate(user):
            return views.choose_finding_template_options(request, tid=template_id, fid=finding_id)

    def test_unauthorized_choose_finding_template_options_fails(self):
        with self.assertRaises(PermissionDenied):
            self.make_request(user_is_staff=False, finding_id=self.finding.id, template_id=self.template.id)

    def test_authorized_choose_finding_template_options_success(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id)
        self.assertEqual(200, result.status_code)

    def test_choose_finding_template_options_with_invalid_finding_fails(self):
        with self.assertRaises(Http404):
            self.make_request(user_is_staff=True, finding_id=99999, template_id=self.template.id)

    def test_choose_finding_template_options_with_invalid_template_fails(self):
        with self.assertRaises(Http404):
            self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=99999)

    def test_choose_finding_template_options_with_valid_finding_and_template_renders_apply_finding_template_view(self):
        result = self.make_request(user_is_staff=True, finding_id=self.finding.id, template_id=self.template.id)
        self.assertContains(result, "<h3> Apply template to a Finding</h3>")


@versioned_fixtures
class TestMkTemplate(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = FindingMother.create()
        self.user = FindingTemplateTestUtil.create_user(is_staff=True)
        self.user.is_superuser = True
        self.user.save()

    def make_request(self, user, finding_id):
        rf = RequestFactory()
        request = rf.get(f"/finding/{finding_id}/mktemplate")
        request.user = user
        request.session = {}
        messages = FallbackStorage(request)
        request._messages = messages
        return views.mktemplate(request, finding_id)

    def test_mktemplate_creates_template_from_finding(self):
        """Test that mktemplate creates a template from an existing finding"""
        # Verify no template exists with this title
        initial_count = Finding_Template.objects.filter(title=self.finding.title).count()
        self.assertEqual(initial_count, 0)

        # Create template from finding
        result = self.make_request(self.user, self.finding.id)

        # Verify redirect to finding view
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result.url, f"/finding/{self.finding.id}")

        # Verify template was created
        templates = Finding_Template.objects.filter(title=self.finding.title)
        self.assertEqual(templates.count(), 1)

        template = templates.first()
        self.assertEqual(template.title, self.finding.title)
        self.assertEqual(template.cwe, self.finding.cwe)
        self.assertEqual(template.severity, self.finding.severity)
        self.assertEqual(template.description, self.finding.description)
        self.assertEqual(template.mitigation, self.finding.mitigation)
        self.assertEqual(template.impact, self.finding.impact)
        self.assertEqual(template.references, self.finding.references)

    def test_mktemplate_fails_when_template_exists(self):
        """Test that mktemplate fails when a template with the same title already exists"""
        # Create a template with the same title first
        existing_template = Finding_Template()
        existing_template.title = self.finding.title
        existing_template.cwe = 0
        existing_template.severity = "Low"
        existing_template.save()

        # Try to create template from finding
        result = self.make_request(self.user, self.finding.id)

        # Verify redirect (still redirects but with error message)
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result.url, f"/finding/{self.finding.id}")

        # Verify only one template exists (the original one)
        templates = Finding_Template.objects.filter(title=self.finding.title)
        self.assertEqual(templates.count(), 1)
        self.assertEqual(templates.first().id, existing_template.id)

    def test_mktemplate_requires_permission(self):
        """Test that mktemplate requires Finding_Add permission"""
        user = FindingTemplateTestUtil.create_user(is_staff=False)
        user.is_superuser = False
        user.save()

        # Should raise PermissionDenied
        with self.assertRaises(PermissionDenied):
            self.make_request(user, self.finding.id)


@versioned_fixtures
class TestAddFindingFromTemplate(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.test = FindingMother.create().test
        self.template = FindingTemplateMother.create()
        self.user = FindingTemplateTestUtil.create_user(is_staff=True)
        self.user.is_superuser = True
        self.user.save()
        # Add user as product member with Maintainer role (has Finding_Add permission)
        maintainer_role = Role.objects.get(name="Maintainer")
        Product_Member(user=self.user, product=self.test.engagement.product, role=maintainer_role).save()

    def make_get_request(self, user, test_id, template_id):
        rf = RequestFactory()
        request = rf.get(f"/test/{test_id}/add_findings/{template_id}")
        request.user = user
        request.session = {}
        messages = FallbackStorage(request)
        request._messages = messages
        with impersonate(user):
            return test_views.add_finding_from_template(request, tid=test_id, fid=template_id)

    def make_post_request(self, user, test_id, template_id, data=None):
        rf = RequestFactory()
        if data is None:
            data = {
                "title": self.template.title,
                "date": timezone.now().date(),
                "severity": self.template.severity,
                "description": self.template.description,
                "mitigation": self.template.mitigation or "",
                "impact": self.template.impact or "",
                "references": self.template.references or "",
                "active": True,
                "verified": True,
                "false_p": False,
                "duplicate": False,
                "out_of_scope": False,
            }
        request = rf.post(f"/test/{test_id}/add_findings/{template_id}", data)
        request.user = user
        request.session = {}
        messages = FallbackStorage(request)
        request._messages = messages
        with impersonate(user):
            return test_views.add_finding_from_template(request, tid=test_id, fid=template_id)

    def test_add_finding_from_template_renders_form(self):
        """Test that GET request renders the form with template data"""
        result = self.make_get_request(self.user, self.test.id, self.template.id)
        self.assertEqual(result.status_code, 200)
        self.assertContains(result, self.template.title)

    def test_add_finding_from_template_creates_finding(self):
        """Test that POST request creates a new finding from template"""
        initial_count = Finding.objects.filter(test=self.test).count()

        result = self.make_post_request(self.user, self.test.id, self.template.id)

        # Should redirect to test view
        self.assertEqual(result.status_code, 302)
        self.assertEqual(result.url, f"/test/{self.test.id}")

        # Verify finding was created
        final_count = Finding.objects.filter(test=self.test).count()
        self.assertEqual(final_count, initial_count + 1)

        # Verify finding has template data
        finding = Finding.objects.filter(test=self.test).order_by("-id").first()
        # Note: title casing may vary, so just check it contains the template title
        self.assertIn(self.template.title.lower(), finding.title.lower())
        self.assertEqual(finding.cwe, self.template.cwe)
        self.assertEqual(finding.severity, self.template.severity)
        self.assertEqual(finding.description, self.template.description)
        self.assertEqual(finding.mitigation, self.template.mitigation or "")
        self.assertEqual(finding.impact, self.template.impact or "")
        self.assertEqual(finding.references, self.template.references or "")

    def test_add_finding_from_template_copies_all_fields(self):
        """Test that all template fields are copied to the finding"""
        # Update template with all new fields
        self.template.cvssv3_score = 7.5
        self.template.cvssv4_score = 8.0
        self.template.fix_available = True
        self.template.fix_version = "1.2.3"
        self.template.planned_remediation_version = "1.3.0"
        self.template.effort_for_fixing = "Low"
        self.template.steps_to_reproduce = "Step 1: Do this\nStep 2: Do that"
        self.template.severity_justification = "This is critical because..."
        self.template.component_name = "test-component"
        self.template.component_version = "1.0.0"
        self.template.notes = "Template note content"
        self.template.save()

        # Set vulnerability IDs
        save_vulnerability_ids_template(self.template, ["CVE-2023-1234", "CVE-2023-5678"])

        # Set endpoints
        save_endpoints_template(self.template, ["https://example.com/api", "https://example.com/admin"])

        result = self.make_post_request(self.user, self.test.id, self.template.id)
        self.assertEqual(result.status_code, 302)

        finding = Finding.objects.filter(test=self.test).order_by("-id").first()

        # Verify all fields were copied
        self.assertEqual(finding.cvssv3_score, 7.5)
        self.assertEqual(finding.cvssv4_score, 8.0)
        self.assertEqual(finding.fix_available, True)
        self.assertEqual(finding.fix_version, "1.2.3")
        self.assertEqual(finding.planned_remediation_version, "1.3.0")
        self.assertEqual(finding.effort_for_fixing, "Low")
        self.assertEqual(finding.steps_to_reproduce, "Step 1: Do this\nStep 2: Do that")
        self.assertEqual(finding.severity_justification, "This is critical because...")
        self.assertEqual(finding.component_name, "test-component")
        self.assertEqual(finding.component_version, "1.0.0")

        # Verify vulnerability IDs were copied
        vulnerability_ids = [vid.vulnerability_id for vid in Vulnerability_Id.objects.filter(finding=finding)]
        self.assertIn("CVE-2023-1234", vulnerability_ids)
        self.assertIn("CVE-2023-5678", vulnerability_ids)

        # Verify endpoints were copied
        if settings.V3_FEATURE_LOCATIONS:
            self.assertTrue(any("example.com/api" in str(loc_ref.location) for loc_ref in finding.locations.all()))
            self.assertTrue(any("example.com/admin" in str(loc_ref.location) for loc_ref in finding.locations.all()))
        else:
            self.assertTrue(any("example.com/api" in str(ep) for ep in finding.endpoints.all()))
            self.assertTrue(any("example.com/admin" in str(ep) for ep in finding.endpoints.all()))

        # Verify note was created
        notes = Notes.objects.filter(finding=finding)
        self.assertTrue(notes.exists())
        note = notes.first()
        self.assertEqual(note.entry, "Template note content")

    def test_add_finding_from_template_requires_permission(self):
        """Test that add_finding_from_template requires Finding_Add permission"""
        unauthorized_user = FindingTemplateTestUtil.create_user(is_staff=False)
        unauthorized_user.is_superuser = False
        unauthorized_user.save()

        # Should raise PermissionDenied
        with self.assertRaises(PermissionDenied):
            self.make_get_request(unauthorized_user, self.test.id, self.template.id)

    def test_add_finding_from_template_updates_template_last_used(self):
        """Test that template.last_used is updated when creating finding"""
        original_last_used = self.template.last_used

        result = self.make_post_request(self.user, self.test.id, self.template.id)
        self.assertEqual(result.status_code, 302)

        # Refresh template from database
        self.template.refresh_from_db()
        self.assertIsNotNone(self.template.last_used)
        if original_last_used:
            self.assertGreaterEqual(self.template.last_used, original_last_used)
