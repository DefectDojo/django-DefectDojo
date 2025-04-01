import datetime
from unittest import skip

from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import Http404
from django.test.client import RequestFactory
from django.utils import timezone

from dojo.finding import views
from dojo.models import Engagement, Finding, Finding_Template, Product, Product_Type, System_Settings, Test, Test_Type

from .dojo_test_case import DojoTestCase


class FindingMother:

    @staticmethod
    def create():
        settings = System_Settings()
        settings.save()

        p = Product()
        p.Name = "Test Product"
        p.Description = "Product for Testing Apply Template functionality"
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
        f.save()


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


class FindingTemplateTestUtil:

    def __init__(self):
        pass

    @staticmethod
    def create_user(is_staff):
        user_count = User.objects.count()
        user = User()
        user.is_staff = is_staff
        user.username = "TestUser" + str(user_count)
        user.save()
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


@skip("outdated so doesn't work with current fixture")
class TestApplyFindingTemplate(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    apply_template_url = "finding/2/2/apply_template_to_finding"

    def setUp(self):
        FindingMother.create()
        FindingTemplateMother.create()

    def make_request(self, user_is_staff, finding_id, template_id, data=None):
        user = FindingTemplateTestUtil.create_user(user_is_staff)

        if data:
            request = FindingTemplateTestUtil.create_post_request(user, self.apply_template_url, data)
        else:
            request = FindingTemplateTestUtil.create_get_request(user, self.apply_template_url)

        return views.apply_template_to_finding(request, finding_id, template_id)

    def test_apply_template_to_finding_with_data_does_not_display_error_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1,
                                   data={"title": "Finding for Testing Apply Template functionality",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertNotContains(result, "There appears to be errors on the form", 302)

    def test_apply_template_to_finding_with_data_returns_to_view_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1,
                                   data={"title": "Finding for Testing Apply Template functionality",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertIsNotNone(result)
        self.assertEqual(302, result.status_code)
        self.assertEqual("/finding/1", result.url)

    def test_apply_template_to_finding_with_data_saves_success(self):
        test_title = "Finding for Testing Apply Template functionality"
        test_cwe = 89
        test_severity = "High"
        test_description = "Finding for Testing Apply Template Functionality"
        test_mitigation = "template mitigation"
        test_impact = "template impact"

        self.make_request(user_is_staff=True, finding_id=1, template_id=1,
                                   data={"title": test_title,
                                    "cwe": test_cwe,
                                    "severity": test_severity,
                                    "description": test_description,
                                    "mitigation": test_mitigation,
                                    "impact": test_impact})

        f = Finding.objects.get(id=1)
        self.assertEqual(test_title, f.title)
        self.assertEqual(test_cwe, f.cwe)
        self.assertEqual(test_severity, f.severity)
        self.assertEqual(test_description, f.description)
        self.assertEqual(test_mitigation, f.mitigation)
        self.assertEqual(test_impact, f.impact)

    def test_unauthorized_apply_template_to_finding_fails(self):
        result = self.make_request(user_is_staff=False, finding_id=1, template_id=1,
                                   data={"title": "Finding for Testing Apply Template functionality",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"},
                                   )
        self.assertEqual(302, result.status_code)
        self.assertIn("login", result.url)

    def test_apply_template_to_finding_with_illegal_finding_fails(self):
        self.make_request(user_is_staff=True, finding_id=None, template_id=1)

    def test_apply_template_to_finding_with_illegal_template_fails(self):
        self.make_request(user_is_staff=True, finding_id=1, template_id=None)

    def test_apply_template_to_finding_with_no_data_returns_view_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1, data=None)
        self.assertIsNotNone(result)
        self.assertEqual(302, result.status_code)
        self.assertEqual("/finding/1", result.url)

    def test_apply_template_to_finding_without_required_field_displays_field_title_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1,
                                   data={"title": "",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertContains(result, "The title is required.")

    def test_apply_template_to_finding_without_required_field_displays_error_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1,
                                   data={"title": "",
                                    "cwe": "89",
                                    "severity": "High",
                                    "description": "Finding for Testing Apply Template Functionality",
                                    "mitigation": "template mitigation",
                                    "impact": "template impact"})
        self.assertContains(result, "There appears to be errors on the form")


@skip("outdated so doesn't work with current fixture")
class TestFindTemplateToApply(DojoTestCase):
    fixtures = ["dojo_testdata.json"]
    choose_template_url = "finding/2/find_template_to_apply"

    def setUp(self):
        FindingMother.create()
        FindingTemplateMother.create()

    def make_request(self, user_is_staff, finding_id, data=None):
        user = FindingTemplateTestUtil.create_user(user_is_staff)

        if data:
            request = FindingTemplateTestUtil.create_post_request(user, self.choose_template_url, data)
        else:
            request = FindingTemplateTestUtil.create_get_request(user, self.choose_template_url)

        return views.find_template_to_apply(request, finding_id)

    def test_unauthorized_find_template_to_apply_fails(self):
        result = self.make_request(user_is_staff=False, finding_id=1)
        self.assertEqual(302, result.status_code)
        self.assertIn("login", result.url)

    def test_authorized_find_template_to_apply_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1)
        self.assertEqual(200, result.status_code)

    def test_find_template_to_apply_displays_templates_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1)
        self.assertContains(result, "Finding Template for Testing Apply Template functionality")

    def test_find_template_to_apply_displays_breadcrumb(self):
        result = self.make_request(user_is_staff=True, finding_id=1)
        self.assertContains(result, "Apply Template to Finding")


@skip("outdated so doesn't work with current fixture")
class TestChooseFindingTemplateOptions(DojoTestCase):
    fixtures = ["dojo_testdata.json"]
    finding_template_options_url = "finding/2/2/choose_finding_template_options"

    def setUp(self):
        FindingMother.create()
        FindingTemplateMother.create()

    def make_request(self, user_is_staff, finding_id, template_id, data=None):
        user = FindingTemplateTestUtil.create_user(user_is_staff)

        if data:
            request = FindingTemplateTestUtil.create_post_request(user, self.finding_template_options_url, data)
        else:
            request = FindingTemplateTestUtil.create_get_request(user, self.finding_template_options_url)

        return views.choose_finding_template_options(request, finding_id, template_id)

    def test_unauthorized_choose_finding_template_options_fails(self):
        result = self.make_request(user_is_staff=False, finding_id=1, template_id=1)
        self.assertEqual(302, result.status_code)
        self.assertIn("login", result.url)

    def test_authorized_choose_finding_template_options_success(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1)
        self.assertEqual(200, result.status_code)

    def test_choose_finding_template_options_with_invalid_finding_fails(self):
        with self.assertRaises(Http404):
            result = self.make_request(user_is_staff=True, finding_id=0, template_id=1)
            self.assertEqual(404, result.status_code)

    def test_choose_finding_template_options_with_invalid_template_fails(self):
        with self.assertRaises(Http404):
            result = self.make_request(user_is_staff=True, finding_id=1, template_id=0)
            self.assertEqual(404, result.status_code)

    def test_choose_finding_template_options_with_valid_finding_and_template_renders_apply_finding_template_view(self):
        result = self.make_request(user_is_staff=True, finding_id=1, template_id=1)
        self.assertContains(result, "<h3> Apply template to a Finding</h3>")
