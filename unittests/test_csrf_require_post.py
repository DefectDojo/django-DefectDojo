"""
Regression tests: state-changing finding/engagement/risk-acceptance UI actions
must not run on GET. A GET has to be rejected (405) so it cannot be triggered by
a cross-origin or stored request that only the browser's safe-method path allows.
"""
from django.urls import reverse

from dojo.models import Finding
from unittests.dojo_test_case import DojoTestCase, versioned_fixtures


@versioned_fixtures
class StateChangingActionsRequirePostTest(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.client.force_login(self.get_test_admin())

    def test_state_changing_actions_reject_get(self):
        # (url_name, args) for every UI action that mutates state.
        # require_POST rejects the method before the view body runs, so the
        # object ids only need to resolve the route, not exist.
        cases = [
            ("simple_risk_accept_finding", (2,)),
            ("risk_unaccept_finding", (2,)),
            ("reopen_finding", (2,)),
            ("touch_finding", (2,)),
            ("close_engagement", (1,)),
            ("reopen_engagement", (1,)),
            ("expire_risk_acceptance", (1, 1)),
            ("reinstate_risk_acceptance", (1, 1)),
            ("delete_risk_acceptance", (1, 1)),
        ]
        for name, args in cases:
            with self.subTest(action=name):
                response = self.client.get(reverse(name, args=args))
                self.assertEqual(
                    response.status_code, 405,
                    f"{name} answered GET with {response.status_code}; must be 405",
                )

    def test_get_does_not_risk_accept_but_post_does(self):
        # Mirror the reported attack shape on the finding risk-accept action.
        finding = Finding.objects.get(id=2)
        product = finding.test.engagement.product
        product.enable_simple_risk_acceptance = True
        product.save()
        finding.active = True
        finding.risk_accepted = False
        finding.save()

        url = reverse("simple_risk_accept_finding", args=(finding.id,))

        # GET (what a stored <img> would issue) must not change anything.
        self.assertEqual(self.client.get(url).status_code, 405)
        finding.refresh_from_db()
        self.assertTrue(finding.active)
        self.assertFalse(finding.risk_accepted)

        # POST (the real button) still works for a permitted user.
        self.assertEqual(self.client.post(url).status_code, 302)
        finding.refresh_from_db()
        self.assertTrue(finding.risk_accepted)
