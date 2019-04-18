import sys
sys.path.append('..')
from dojo.models import Product, Tool_Type, Tool_Configuration, Endpoint, Tool_Product_Settings
from django.test import TransactionTestCase
from django.contrib.auth.models import User
from django.core.management import call_command
from tagging.models import Tag
from django.conf import settings
from StringIO import StringIO
import os


class ReportScheduleTestUtil:

    def __init__(self):
        pass

    @staticmethod
    def create_user(is_staff):
        user = User()
        user.is_staff = is_staff
        user.save()
        return user

    @staticmethod
    def create_get_request(user, path):
        rf = RequestFactory()
        get_request = rf.get(path)
        get_request.user = user
        get_request.session = dict()

        return get_request

    @staticmethod
    def create_post_request(user, path, data):
        rf = RequestFactory()
        post_request = rf.post(path, data=data)
        post_request.user = user
        post_request.session = dict()
        messages = FallbackStorage(post_request)
        setattr(post_request, '_messages', messages)

        return post_request


class TestReportSchedule(TestCase):

    report_json = '[{"report-options":[{"name":"report_name","value":"Test+Report"},{"name":"include_finding_notes","value":"0"},{"name":"include_finding_images","value":"0"},{"name":"report_type","value":"AsciiDoc"}]},{"wysiwyg-content":[{"name":"hidden_content","value":"hello+world"},{"name":"heading","value":"WYSIWYG+Content"}]}]'
    default_add = {
        "report": 1,
        "event": 1,
        "time_unit": 1,
        "time_count": 1,
        "recipients": "john.doe@example.com",
    }

    def setUp(self):
        u = User()
        u.is_staff = True
        u.id = 1
        u.save()
        
        r = Report()
        r.id = 1
        r.name = "Test Report"
        r.type = "Custom"
        r.format = "AsciiDoc"
        r.requester = u
        r.options = self.report_json
        r.host = "http://example.com"
        r.save()

        call_command('loaddata', 'dojo/fixtures/system_settings', verbosity=0)

    def make_request(self, user_is_staff, endpoint, data=None):
        user = ReportScheduleTestUtil.create_user(user_is_staff)
        endpoint = 'reports/scheduler/' + endpoint

        if data:
            request = ReportScheduleTestUtil.create_post_request(user, endpoint, data)
        else:
            request = ReportScheduleTestUtil.create_get_request(user, endpoint)

        v = views.plan_engagements(request)

        return v

    def test_unauthorized_report_scheduler_fails(self):
        v = self.make_request(False, "add")
        self.assertIsInstance(v, HttpResponseRedirect)

    def test_report_scheduler_returns_view(self):
        v = self.make_request(True, "add")
        self.assertIsNotNone(v)
        self.assertContains(v, 'id_report')

    def test_report_scheduler_add(self):
        v = self.make_request(True, "add", self.default_add)
        self.assertIsInstance(v, HttpResponseRedirect)

    def test_report_scheduler_send(self):
        out = StringIO()
        call_command('send_scheduled_reports', stdout=out)
        self.assertNotIn("Denied tool run", out.getvalue())
        self.assertIn("Hello World", out.getvalue())
