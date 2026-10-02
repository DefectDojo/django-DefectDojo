# from unittest import skip
import logging
from unittest.mock import patch
from urllib.parse import urlencode

from celery.result import AsyncResult
from django.contrib.messages import get_messages
from django.urls import reverse
from vcr import VCR

from dojo.models import Engagement
from unittests.dojo_test_case import DojoTestCase, DojoVCRTestCase, get_unit_tests_path, versioned_fixtures
from unittests.test_jira_config_engagement import JIRAConfigEngagementBase

logger = logging.getLogger(__name__)


@versioned_fixtures
class JIRAConfigEngagementEpicTest(DojoVCRTestCase, JIRAConfigEngagementBase):
    fixtures = ["dojo_testdata.json"]

    product_id = 999

    def __init__(self, *args, **kwargs):
        # TODO: remove __init__ if it does nothing...
        DojoVCRTestCase.__init__(self, *args, **kwargs)

    def assert_cassette_played(self):
        if True:  # set to True when committing. set to False when recording new test cassettes
            self.assertTrue(self.cassette.all_played)

    def _get_vcr(self, **kwargs):
        my_vcr = super(DojoVCRTestCase, self)._get_vcr(**kwargs)
        my_vcr.record_mode = "once"
        my_vcr.path_transformer = VCR.ensure_suffix(".yaml")
        my_vcr.filter_headers = ["Authorization", "X-Atlassian-Token"]
        my_vcr.cassette_library_dir = str(get_unit_tests_path() / "vcr" / "jira")
        # filters headers doesn't seem to work for cookies, so use callbacks to filter cookies from being recorded
        my_vcr.before_record_request = self.before_record_request
        my_vcr.before_record_response = self.before_record_response
        return my_vcr

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.user = self.get_test_admin()
        self.client.force_login(self.user)
        self.user.usercontactinfo.block_execution = True
        self.user.usercontactinfo.save()
        # product 3 has no jira project config, double check to make sure someone didn't molest the fixture
        # running this in __init__ throws database access denied error
        self.product_id = 1  # valid JIRA config
        # product = Product.objects.get(id=self.product_id)
        # self.assertIsNone(jira_helper.get_jira_project(product))

    def get_new_engagement_with_jira_project_data_and_epic_mapping(self):
        return {
            "name": "new engagement",
            "description": "new description",
            "lead": 1,
            "product": self.product_id,
            "target_start": "2070-11-27",
            "target_end": "2070-12-04",
            "status": "Not Started",
            "jira-project-form-jira_instance": 2,
            "jira-project-form-project_key": "NTEST",
            "jira-project-form-epic_issue_type_name": "Epic",
            "jira-project-form-enabled": "True",
            "jira-project-form-product_jira_sla_notification": "on",
            "jira-project-form-enable_engagement_epic_mapping": "on",
            "jira-epic-form-push_to_jira": "on",
        }

    def add_engagement_with_jira_project_and_epic_mapping(self, expected_delta_jira_project_db=0, expect_redirect_to=None, *, expect_200=False):
        return self.add_engagement_jira_with_data(self.get_new_engagement_with_jira_project_data_and_epic_mapping(), expected_delta_jira_project_db, expect_redirect_to=expect_redirect_to, expect_200=expect_200)

    def test_add_engagement_with_jira_project_and_epic_mapping(self):
        engagement = self.add_engagement_with_jira_project_and_epic_mapping(expected_delta_jira_project_db=1)
        self.assertIsNotNone(engagement)
        self.assertIsNotNone(engagement.jira_project)
        self.assertTrue(engagement.has_jira_issue)


@versioned_fixtures
class JIRAEpicMappingAsyncPushTest(DojoTestCase):

    """
    Regression: an engagement edit with epic mapping enabled returned a 500
    ("TypeError: cannot unpack non-iterable AsyncResult object") whenever the
    epic push was dispatched to a Celery worker instead of run inline.

    JIRAConfigEngagementEpicTest above sets block_execution=True, which forces
    the foreground path where push_to_jira returns a (success, message) tuple.
    Leaving block_execution at its default sends the push to a worker, and the
    return value is then an AsyncResult -- the shape real users hit.

    push_to_jira is patched so no Jira calls are made and no cassette is needed.
    The POST inherits the jira config from the product rather than setting an
    engagement-level one, which is a no-op in process_jira_project_form (there
    is no engagement-level JIRA_Project to remove) and so contacts no Jira
    instance either -- while get_jira_project() still resolves the product's
    config through inheritance, so the epic push is still attempted.
    """

    fixtures = ["dojo_testdata.json"]

    # engagement 2 belongs to product 1, whose JIRA_Project has
    # enable_engagement_epic_mapping set, inherited via get_jira_project()
    engagement_id = 2

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.user = self.get_test_admin()
        self.client.force_login(self.user)
        # deliberately NOT setting block_execution: the default sends the push
        # to a worker, which is the path that used to raise
        self.user.usercontactinfo.block_execution = False
        self.user.usercontactinfo.save()

    def _post_engagement_edit(self, engagement):
        data = {
            "name": engagement.name,
            "description": engagement.description,
            "lead": 1,
            "product": engagement.product.id,
            "target_start": "2070-11-27",
            "target_end": "2070-12-04",
            "status": "Not Started",
            # keep inheriting the product's jira config so the project form is a
            # no-op and only the epic push is exercised
            "jira-project-form-inherit_from_product": "on",
            "jira-project-form-epic_issue_type_name": "Epic",
            "jira-project-form-enabled": "True",
            "jira-epic-form-push_to_jira": "on",
        }
        return self.client.post(
            reverse("edit_engagement", args=(engagement.id,)),
            urlencode(data),
            content_type="application/x-www-form-urlencoded",
        )

    def test_edit_engagement_with_queued_epic_push_redirects(self):
        engagement = Engagement.objects.get(id=self.engagement_id)
        queued = AsyncResult("11111111-2222-3333-4444-555555555555")

        with patch("dojo.jira.helper.push_to_jira", return_value=queued) as push:
            response = self._post_engagement_edit(engagement)

        push.assert_called_once()
        self.assertEqual(
            302, response.status_code,
            msg=f"expected a redirect after a queued epic push, got {response.status_code}",
        )
        self.assertEqual(
            reverse("view_engagement", args=(engagement.id,)), response.url,
            msg=f"expected redirect to the engagement, got {response.url}",
        )

    def test_edit_engagement_with_foreground_epic_push_failure_rerenders(self):
        """Control: a foreground failure tuple must still be treated as an error."""
        engagement = Engagement.objects.get(id=self.engagement_id)

        with patch("dojo.jira.helper.push_to_jira", return_value=(False, "jira exploded")) as push:
            response = self._post_engagement_edit(engagement)

        push.assert_called_once()
        self.assertEqual(
            200, response.status_code,
            msg=f"expected the form to re-render on push failure, got {response.status_code}",
        )


@versioned_fixtures
class JIRAPushFailureReportingTest(DojoTestCase):

    """
    Regression: the finding "push to Jira" endpoint reported success even when
    the push failed, because it tested push()'s raw return value for truthiness
    and a (False, message) tuple is truthy. The alert-danger branch could never
    be reached.
    """

    fixtures = ["dojo_testdata.json"]

    finding_id = 2

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.user = self.get_test_admin()
        self.client.force_login(self.user)

    def _push(self, push_return):
        with patch("dojo.jira.helper.push_to_jira", return_value=push_return):
            response = self.client.post(
                reverse("finding_push_to_jira", args=(self.finding_id,)),
            )
        tags = [m.extra_tags for m in get_messages(response.wsgi_request)]
        return response, tags

    def test_failed_push_is_reported_as_an_error(self):
        response, tags = self._push((False, "jira exploded"))

        self.assertEqual(200, response.status_code)
        self.assertIn(
            "alert-danger", tags,
            msg=f"a failed push must raise an alert-danger message, got tags={tags}",
        )

    def test_queued_push_is_reported_as_a_success(self):
        """Control: a queued push has not failed, so it must not raise an error alert."""
        queued = AsyncResult("11111111-2222-3333-4444-555555555555")

        response, tags = self._push(queued)

        self.assertEqual(200, response.status_code)
        self.assertIn(
            "alert-success", tags,
            msg=f"a queued push must report success, got tags={tags}",
        )
        self.assertNotIn("alert-danger", tags)
