from .dojo_test_case import DojoTestCase
from dojo.models import Product
from dojo.jira_link import helper as jira_helper
# from unittest import skip
import logging

logger = logging.getLogger(__name__)


class JIRATemplatetTest(DojoTestCase):
    fixtures = ['dojo_testdata.json']

    def __init__(self, *args, **kwargs):
        DojoTestCase.__init__(self, *args, **kwargs)

    def setUp(self):
        self.system_settings(enable_jira=True)

    def test_get_jira_issue_template_dir_from_project(self):
        product = Product.objects.get(id=1)
        jira_project = jira_helper.get_jira_project(product)
        # filepathfield contains full path
        jira_project.issue_template_dir = 'issue-trackers/jira_full_extra'
        jira_project.save()

        self.assertEqual(jira_helper.get_jira_issue_template(product), 'issue-trackers/jira_full_extra/jira-description.tpl')

    def test_get_jira_issue_template_dir_from_instance(self):
        product = Product.objects.get(id=1)
        jira_project = jira_helper.get_jira_project(product)
        jira_project.issue_template_dir = None
        jira_project.save()
        self.assertEqual(jira_helper.get_jira_issue_template(product), 'issue-trackers/jira_full/jira-description.tpl')

    def test_get_jira_project_and_instance_no_issue_template_dir(self):
        product = Product.objects.get(id=1)
        jira_project = jira_helper.get_jira_project(product)
        jira_project.issue_template_dir = None
        jira_project.save()
        jira_instance = jira_helper.get_jira_instance(product)
        jira_instance.issue_template_dir = None
        jira_instance.save()
        # no template should return default
        self.assertEqual(jira_helper.get_jira_issue_template(product), 'issue-trackers/jira_full/jira-description.tpl')
