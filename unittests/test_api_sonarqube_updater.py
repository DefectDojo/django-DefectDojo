from dojo.models import Tool_Configuration, Tool_Type
from dojo.tools.api_sonarqube.updater import SonarQubeApiUpdater

from .dojo_test_case import DojoTestCase


class TestSonarQubeApiUpdater(DojoTestCase):

    def setUp(self):
        tool_type = Tool_Type.objects.create(name="SonarQube")
        Tool_Configuration.objects.create(name="SonarQube", tool_type=tool_type, authentication_type="API")

        self.updater = SonarQubeApiUpdater()

    def test_transitions_for_sonarqube_issue_from_open_to_confirmed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("OPEN", "CONFIRMED", is_hotspot=False),
            ["confirm"],
        )

    def test_transitions_for_sonarqube_issue_from_open_to_resolved_fixed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("OPEN", "RESOLVED / FIXED", is_hotspot=False),
            ["resolve"],
        )

    def test_transitions_for_sonarqube_issue_from_reopened_to_resolved_fixed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("REOPENED", "RESOLVED / FIXED", is_hotspot=False),
            ["resolve"],
        )

    def test_transitions_for_sonarqube_issue_from_reopened_to_confirmed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("REOPENED", "CONFIRMED", is_hotspot=False),
            ["confirm"],
        )

    def test_transitions_for_sonarqube_issue_from_resolved_fixed_to_confirmed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("RESOLVED / FIXED", "CONFIRMED", is_hotspot=False),
            ["reopen", "confirm"],
        )

    def test_transitions_for_sonarqube_issue_from_resolved_fixed_to_resolved_falsepositive(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("RESOLVED / FIXED", "RESOLVED / FALSE-POSITIVE", is_hotspot=False),
            ["reopen", "falsepositive"],
        )

    def test_transitions_for_sonarqube_issue_from_resolved_fixed_to_resolved_wontfix(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("RESOLVED / FIXED", "RESOLVED / WONTFIX", is_hotspot=False),
            ["reopen", "wontfix"],
        )

    def test_transitions_for_sonarqube_issue_from_confirmed_to_reopened(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("CONFIRMED", "REOPENED", is_hotspot=False),
            ["unconfirm"],
        )

    def test_transitions_for_sonarqube_issue_from_confirmed_to_resolved_fixed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("CONFIRMED", "RESOLVED / FIXED", is_hotspot=False),
            ["resolve"],
        )

    def test_transitions_for_sonarqube_issue_from_confirmed_to_resolved_wontfix(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("CONFIRMED", "RESOLVED / WONTFIX", is_hotspot=False),
            ["wontfix"],
        )

    def test_transitions_for_sonarqube_issue_from_confirmed_to_resolved_falsepositive(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("CONFIRMED", "RESOLVED / FALSE-POSITIVE", is_hotspot=False),
            ["falsepositive"],
        )

    def test_transitions_for_sonarqube_issue_open_reopen_status_same(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("OPEN", "OPEN", is_hotspot=False),
            None,
        )

    def test_transitions_for_sonarqube_issue_open_reopen_status_different(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("OPEN", "REOPENED", is_hotspot=False),
            None,
        )

    def test_transitions_for_sonarqube_issue_fake_status(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("FAKE_STATUS", "RESOLVED / FIXED", is_hotspot=False),
            None,
        )

    def test_transitions_for_sonarqube_issue_fake_target(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("RESOLVED / FIXED", "FAKE_STATUS", is_hotspot=False),
            None,
        )

    # Tests for hotspot transitions
    def test_transitions_for_sonarqube_hotspot_from_to_review_to_resolved_falsepositive(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("TO_REVIEW", "RESOLVED / FALSE-POSITIVE", is_hotspot=True),
            [{"status": "REVIEWED", "resolution": "SAFE"}],
        )

    def test_transitions_for_sonarqube_hotspot_from_to_review_to_resolved_fixed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("TO_REVIEW", "RESOLVED / FIXED", is_hotspot=True),
            [{"status": "REVIEWED", "resolution": "FIXED"}],
        )

    def test_transitions_for_sonarqube_hotspot_from_to_review_to_resolved_wontfix(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("TO_REVIEW", "RESOLVED / WONTFIX", is_hotspot=True),
            [{"status": "REVIEWED", "resolution": "ACKNOWLEDGED"}],
        )

    def test_transitions_for_sonarqube_hotspot_from_reviewed_to_open(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("REVIEWED", "OPEN", is_hotspot=True),
            [{"status": "TO_REVIEW", "resolution": None}],
        )

    def test_transitions_for_sonarqube_hotspot_from_reviewed_to_reopened(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("REVIEWED", "REOPENED", is_hotspot=True),
            [{"status": "TO_REVIEW", "resolution": None}],
        )

    def test_transitions_for_sonarqube_hotspot_from_reviewed_to_confirmed(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("REVIEWED", "CONFIRMED", is_hotspot=True),
            [{"status": "TO_REVIEW", "resolution": None}],
        )

    def test_transitions_for_sonarqube_hotspot_same_status(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("TO_REVIEW", "TO_REVIEW", is_hotspot=True),
            None,
        )

    def test_transitions_for_sonarqube_hotspot_fake_status(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("FAKE_STATUS", "REVIEWED", is_hotspot=True),
            None,
        )

    def test_transitions_for_sonarqube_hotspot_fake_target(self):
        self.assertEqual(
            self.updater.get_sonarqube_required_transitions_for("TO_REVIEW", "FAKE_STATUS", is_hotspot=True),
            None,
        )
