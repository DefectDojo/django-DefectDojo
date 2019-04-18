import sys
sys.path.append('..')
from dojo.models import Product
from dojo.models import Endpoint
from dojo.engagement import views
from django.test import TestCase
from django.test.client import RequestFactory
from django.contrib.auth.models import User
from django.contrib.messages.storage.fallback import FallbackStorage
from django.http import HttpResponseRedirect
from django.core.management import call_command
from tagging.models import Tag
from django.utils import timezone


class EngagementPlannerTestUtil:

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


class TestEngagementPlanner(TestCase):

    plan_engagement_url = 'engagement/plan'
    default_plan = {
        'products': ['1', '2'],
        'from_date': timezone.now().strftime("%Y-%m-%d"),
        'to_date': (timezone.now() + timezone.timedelta(days=365)).strftime("%Y-%m-%d"),
        'products_order': '-business_criticality',
        'allowed_days': ['0', '1', '2', '3', '4'],
        'days_per_engagement': '5',
        'parallel_engagements': '1',
        'break_days': '5',
        'break_interval': '20'
    }

    def setUp(self):
        p1 = Product()
        p1.name = 'Test Product 1'
        p1.description = 'Product for Testing Endpoint functionality'
        p1.save()

        e1 = Endpoint()
        e1.product = p1
        e1.host = 'http://example.com'
        e1.export_tool = True
        e1.save()

        p2 = Product()
        p2.name = 'Test Product 2'
        p2.description = 'Product for Testing Endpoint functionality'
        p2.save()

        e2 = Endpoint()
        e2.product = p2
        e2.host = 'http://example2.com'
        e2.export_tool = True
        e2.save()

        call_command('loaddata', 'dojo/fixtures/system_settings', verbosity=0)

    def make_request(self, user_is_staff, data=None):
        user = EngagementPlannerTestUtil.create_user(user_is_staff)

        if data:
            request = EngagementPlannerTestUtil.create_post_request(user, self.plan_engagement_url, data)
        else:
            request = EngagementPlannerTestUtil.create_get_request(user, self.plan_engagement_url)

        v = views.plan_engagements(request)

        return v

    def test_unauthorized_engagement_planner_fails(self):
        v = self.make_request(False)
        self.assertIsInstance(v, HttpResponseRedirect)

    def test_engagement_planner_returns_view(self):
        v = self.make_request(True)
        self.assertIsNotNone(v)
        self.assertContains(v, 'id_products_0')

    def test_engagement_planner_plans_simple(self):
        v = self.make_request(True, self.default_plan)
        self.assertIsInstance(v, HttpResponseRedirect)
