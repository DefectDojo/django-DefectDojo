import datetime

from crum import impersonate
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.core.exceptions import PermissionDenied
from django.http import Http404
from django.test.client import RequestFactory
from django.utils import timezone

from dojo.finding import views
from dojo.models import (
    Engagement,
    Finding,
    Finding_Template,
    Product,
    Product_Member,
    Product_Type,
    Role,
    System_Settings,
    Test,
    Test_Type,
)

from .dojo_test_case import DojoTestCase


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
