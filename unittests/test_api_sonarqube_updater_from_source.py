from dojo.models import Finding, Risk_Acceptance
from dojo.tools.api_sonarqube.updater_from_source import SonarQubeApiUpdaterFromSource

from .dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class TestSonarQubeApiUpdaterFromSource(DojoTestCase):

    """
    Covers the finding-status side of syncing a SonarQube issue status back onto a finding.

    Every branch except WONTFIX called a helper that does not exist
    (`ra_helper.remove_finding.from_any_risk_acceptance`), so any sync of an open, confirmed,
    fixed or false-positive issue raised AttributeError.
    """

    fixtures = ["dojo_testdata.json"]

    def accepted_finding(self):
        """Return a finding that is risk accepted through a real risk acceptance."""
        finding = Finding.objects.get(id=2)
        risk_acceptance = Risk_Acceptance.objects.create(
            name="Accepted for the updater test",
            owner=self.get_test_admin(),
            decision=Risk_Acceptance.TREATMENT_ACCEPT,
        )
        risk_acceptance.accepted_findings.set([finding])
        finding.test.engagement.risk_acceptance.add(risk_acceptance)
        finding.active = False
        finding.risk_accepted = True
        finding.save()
        return finding

    def test_open_status_drops_the_risk_acceptance(self):
        finding = self.accepted_finding()

        SonarQubeApiUpdaterFromSource.update_finding_status(finding, "OPEN")

        finding.refresh_from_db()
        self.assertTrue(finding.active)
        self.assertEqual(0, finding.risk_acceptance_set.count())

    def test_false_positive_status_drops_the_risk_acceptance(self):
        finding = self.accepted_finding()

        SonarQubeApiUpdaterFromSource.update_finding_status(finding, "FALSE-POSITIVE")

        finding.refresh_from_db()
        self.assertTrue(finding.false_p)
        self.assertEqual(0, finding.risk_acceptance_set.count())

    def test_wontfix_status_accepts_the_finding(self):
        finding = Finding.objects.get(id=3)

        SonarQubeApiUpdaterFromSource.update_finding_status(finding, "WONTFIX")

        finding.refresh_from_db()
        # the finding actually reads as accepted, which it did not before
        self.assertTrue(finding.risk_accepted)
        self.assertFalse(finding.active)

        risk_acceptance = finding.risk_acceptance_set.get()
        # named and reachable, rather than an unnamed row nobody can find
        self.assertTrue(risk_acceptance.name)
        self.assertIn(risk_acceptance, finding.test.engagement.risk_acceptance.all())
        self.assertIsNotNone(risk_acceptance.expiration_date)
