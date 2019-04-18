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


class TestToolRun(TransactionTestCase):
    
    project_root = os.path.abspath(os.path.dirname(__name__))
    devnull = open(os.devnull, 'w')

    def setUp(self):
        u = User()
        u.name = 'Test User 1'
        u.is_staff = True
		u.id = 1
        u.save()

        p = Product()
        p.name = 'Test Product 1'
        p.description = 'Product for Testing Endpoint functionality'
        p.save()

        e = Endpoint()
        e.product = p
        e.host = 'http://example.com'
        e.export_tool = True
        e.save()

        tt = Tool_Type()
        tt.name = 'Tool Type 1'
        tt.description = 'Tool Type for testing run functionality'
        tt.save()

        tc = Tool_Configuration()
        tc.name = 'Tool Configuration 1'
        tc.url = 'ssh://localhost' + self.project_root + '/dojo/fixtures/tool_run.sh'
        tc.tool_type = tt
        tc.save()

        tp = Tool_Product_Settings()
        tp.name = 'Tool Product Configuration 1'
        tp.product = p
        tp.tool_configuration = tc
        tp.url = ""
        tp.save()

        call_command('loaddata', 'dojo/fixtures/system_settings', verbosity=0)

    def test_tool_run_invalid_engagement(self):
        with self.assertRaises(SystemExit) as cm:
            call_command('run_tool', config=1, engagement=999, stdout=self.devnull)

        self.assertEqual(cm.exception.code, 0)

    def test_tool_run_invalid_config(self):
        with self.assertRaises(SystemExit) as cm:
            call_command('run_tool', config=999, engagement=0, stdout=self.devnull)

        self.assertEqual(cm.exception.code, 0)

    def test_tool_run_execute_localhost_denied(self):
        out = StringIO()
        call_command('run_tool', config=1, engagement=0, stdout=out)
        self.assertIn("Denied tool run", out.getvalue())

    def test_tool_run_execute_simple(self):
        settings.ALLOW_TOOL_RUN["ssh-localhost"] = True

        out = StringIO()
        call_command('run_tool', config=1, engagement=0, stdout=out)
        self.assertNotIn("Denied tool run", out.getvalue())
        self.assertIn("Hello World", out.getvalue())
