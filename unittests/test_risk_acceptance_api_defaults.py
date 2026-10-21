import datetime as dt

from django.test import override_settings
from django.utils import timezone
from rest_framework.reverse import reverse
from rest_framework.test import APIClient, APITestCase

from dojo.authorization.models import Product_Type_Member, Role
from dojo.authorization.roles_permissions import Roles
from dojo.finding.helper import save_vulnerability_ids
from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Risk_Acceptance,
    System_Settings,
    Test,
    Test_Type,
    User,
)
from dojo.risk_acceptance import helper as ra_helper

START = dt.datetime(2000, 1, 1, tzinfo=dt.UTC)
END = dt.datetime(2000, 2, 1, tzinfo=dt.UTC)


@override_settings(SECURE_SSL_REDIRECT=False)
class RiskAcceptanceApiDefaultsBase(APITestCase):

    @classmethod
    def setUpTestData(cls):
        cls.user = User.objects.create(username="ra_defaults", first_name="Ra", last_name="Defaults", is_staff=True)
        cls.product_type = Product_Type.objects.create(name="Defaults Type")
        Product_Type_Member.objects.create(product_type=cls.product_type, user=cls.user, role=Role.objects.get(id=Roles.Owner))
        cls.product = Product.objects.create(prod_type=cls.product_type, name="Defaults Product", description="d", enable_full_risk_acceptance=True)
        cls.engagement = Engagement.objects.create(product=cls.product, target_start=START, target_end=END)
        test_type = Test_Type.objects.create(name="Defaults Scan", static_tool=True)
        cls.test = Test.objects.create(engagement=cls.engagement, test_type=test_type, target_start=START, target_end=END)

    def setUp(self):
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)

    def make_finding(self, cve, **fields):
        finding = Finding.objects.create(**{
            "test": self.test, "title": f"Finding {cve}", "cve": cve, "severity": "High", "verified": True,
            "active": True, "description": "d", "reporter": self.user, "numerical_severity": "S1", **fields,
        })
        save_vulnerability_ids(finding, [cve])
        return finding

    def set_window(self, days):
        system_settings = System_Settings.objects.get(no_cache=True)
        system_settings.risk_acceptance_form_default_days = days
        system_settings.save()

    def assert_expires_in(self, risk_acceptance, days):
        risk_acceptance.refresh_from_db()
        if days is None:
            self.assertIsNone(risk_acceptance.expiration_date, msg=f"persisted expiration_date={risk_acceptance.expiration_date}")
            return
        expected = timezone.now() + dt.timedelta(days=days)
        self.assertIsNotNone(risk_acceptance.expiration_date, msg="persisted expiration_date=None")
        self.assertLess(
            abs(risk_acceptance.expiration_date - expected), dt.timedelta(minutes=5),
            msg=f"expected about {expected}, persisted={risk_acceptance.expiration_date}",
        )


# Regression: the accept_risks actions created acceptances with no expiration date, so they never
# expired, while the classic form and reinstate use the Default Risk Acceptance Days window.
class TestAcceptRisksDefaultExpiration(RiskAcceptanceApiDefaultsBase):

    ROUTES = (
        ("test-accept-risks", "test"),
        ("engagement-accept-risks", "engagement"),
        ("finding-accept-risks", None),
    )

    def accept(self, route, kind, **extra):
        finding = self.make_finding(f"CVE-2026-{Finding.objects.count() + 1000}")
        kwargs = {"pk": getattr(self, kind).id} if kind else {}
        body = [{"vulnerability_id": finding.cve, "justification": "j", "accepted_by": "a", **extra}]
        response = self.client.post(reverse(route, kwargs=kwargs), data=body, format="json")
        self.assertEqual(response.status_code, 201, response.content)
        return finding.risk_acceptance_set.get()

    def test_each_route_follows_the_window(self):
        # (configured setting, expected days): a null setting reads as 180, 0 means no default.
        for setting, expected in ((30, 30), (None, ra_helper.DEFAULT_RISK_ACCEPTANCE_EXPIRATION_DAYS), (0, None), (-3, None)):
            self.set_window(setting)
            for route, kind in self.ROUTES:
                with self.subTest(route=route, setting=setting):
                    self.assert_expires_in(self.accept(route, kind), expected)

    def test_an_explicit_date_and_an_explicit_null_are_kept(self):
        self.set_window(30)
        chosen = (timezone.now() + dt.timedelta(days=7)).replace(microsecond=0)
        for route, kind in self.ROUTES:
            with self.subTest(route=route):
                dated = self.accept(route, kind, expiration_date=chosen.isoformat())
                dated.refresh_from_db()
                self.assertEqual(dated.expiration_date, chosen)
                self.assert_expires_in(self.accept(route, kind, expiration_date=None), None)


# Regression: a plain POST /api/v2/risk_acceptance/ that omitted expiration_date stored none, so the
# acceptance never expired; and a finding could be added to a second acceptance.
class TestRiskAcceptanceCreateDefaultsAndOnePerFinding(RiskAcceptanceApiDefaultsBase):

    def create(self, findings, **extra):
        body = {"name": "RA", "owner": self.user.id, "recommendation": "A", "decision": "A",
                "accepted_findings": [f.id for f in findings], **extra}
        return self.client.post(reverse("risk_acceptance-list"), data=body, format="json")

    def test_an_omitted_date_gets_the_window_and_null_never_expires(self):
        self.set_window(30)
        response = self.create([self.make_finding("CVE-2026-1")])
        self.assertEqual(response.status_code, 201, response.content)
        self.assert_expires_in(Risk_Acceptance.objects.get(id=response.json()["id"]), 30)

        response = self.create([self.make_finding("CVE-2026-2")], expiration_date=None)
        self.assertEqual(response.status_code, 201, response.content)
        self.assert_expires_in(Risk_Acceptance.objects.get(id=response.json()["id"]), None)

        self.set_window(0)
        response = self.create([self.make_finding("CVE-2026-3")])
        self.assertEqual(response.status_code, 201, response.content)
        self.assert_expires_in(Risk_Acceptance.objects.get(id=response.json()["id"]), None)

    def test_a_finding_accepted_elsewhere_is_refused(self):
        finding = self.make_finding("CVE-2026-4")
        self.assertEqual(self.create([finding]).status_code, 201)

        response = self.create([finding])
        self.assertEqual(response.status_code, 400, response.content)
        self.assertIn("accepted_findings", response.json())
        self.assertEqual(finding.risk_acceptance_set.count(), 1, msg=f"persisted memberships={finding.risk_acceptance_set.count()}")

    def test_a_simple_risk_accepted_finding_is_refused(self):
        finding = self.make_finding("CVE-2026-5", risk_accepted=True, active=False)
        response = self.create([finding])
        self.assertEqual(response.status_code, 400, response.content)
        self.assertFalse(finding.risk_acceptance_set.exists())

    def test_patch_refuses_adding_a_finding_accepted_elsewhere_but_keeps_its_own(self):
        own, other = self.make_finding("CVE-2026-6"), self.make_finding("CVE-2026-7")
        first = Risk_Acceptance.objects.get(id=self.create([own]).json()["id"])
        self.assertEqual(self.create([other]).status_code, 201)

        url = reverse("risk_acceptance-detail", kwargs={"pk": first.id})
        response = self.client.patch(url, data={"accepted_findings": [own.id, other.id]}, format="json")
        self.assertEqual(response.status_code, 400, response.content)
        self.assertEqual(list(first.accepted_findings.values_list("id", flat=True)), [own.id])

        response = self.client.patch(url, data={"accepted_findings": [own.id]}, format="json")
        self.assertEqual(response.status_code, 200, response.content)

    def test_a_finding_from_an_expired_acceptance_may_be_accepted_again(self):
        finding = self.make_finding("CVE-2026-8")
        expired = Risk_Acceptance.objects.get(id=self.create([finding]).json()["id"])
        ra_helper.expire_now(expired)
        finding.refresh_from_db()
        self.assertFalse(finding.risk_accepted)

        response = self.create([finding])
        self.assertEqual(response.status_code, 201, response.content)
