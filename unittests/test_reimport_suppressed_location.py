"""
Regression tests: reimport must not fold a newly reported host into a suppressed finding.

Many network scanners build their matching key from the title, severity and vulnerability ids
alone, so one issue reported on several hosts shares one key. Reimport used to take the first
finding with that key, which folded every host into the lowest-id finding. When that finding had
been marked false positive, out of scope or risk accepted for its own host, every host that later
reported the same issue was silently covered by that decision and never shown. Reimport also
matched a host's report against another host's finding, closing the right finding and keeping the
wrong one open.

The rule pinned here: a suppressed finding only absorbs an incoming finding whose locations it
already has; otherwise the incoming finding becomes a new finding. Among findings that share a
key, the one that already has the incoming locations is matched first.
"""
import json
import tempfile
from pathlib import Path

from django.test import override_settings

from dojo.location.feature import locations_enabled
from dojo.models import Finding, Test
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures

SCAN_TYPE = "Generic Findings Import"


def _finding(host):
    # Plugin text, as network scanners write it: it names the flaw, not the host. So the
    # matching key is the same for every host.
    return {
        "title": "SMB Signing not required",
        "severity": "Medium",
        "cwe": 287,
        "description": "Signing is not required on the remote SMB server.",
        "static_finding": False,
        "dynamic_finding": True,
        "endpoints": [f"{host}:445"],
    }


def _hosts(finding):
    if locations_enabled():
        return sorted(ref.location.url.host for ref in finding.locations.select_related("location__url"))
    return sorted(finding.endpoints.values_list("host", flat=True))


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class ReimportSuppressedLocationTest(DojoAPITestCase):

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.login_as_admin()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _scan(self, name, *hosts):
        path = Path(self.tmp.name) / f"{name}.json"
        path.write_text(json.dumps({"findings": [_finding(h) for h in hosts]}), encoding="utf-8")
        return str(path)

    def _import(self, *hosts):
        result = self.import_scan_with_params(self._scan("import", *hosts), scan_type=SCAN_TYPE, minimum_severity="Info")
        return result["test"]

    def _reimport(self, test_id, *hosts):
        self.reimport_scan_with_params(test_id, self._scan("reimport", *hosts), scan_type=SCAN_TYPE, minimum_severity="Info")

    def _findings(self, test_id):
        return list(Finding.objects.filter(test=Test.objects.get(id=test_id)).order_by("id"))

    def _suppress(self, finding, **status):
        Finding.objects.filter(pk=finding.pk).update(active=False, **status)

    # ---- a suppressed finding keeps only its own hosts ------------------------------------

    def test_new_host_is_not_folded_into_a_false_positive(self):
        test_id = self._import("host-a.example.test")
        (original,) = self._findings(test_id)
        self._suppress(original, false_p=True)

        self._reimport(test_id, "host-a.example.test", "host-b.example.test")

        findings = self._findings(test_id)
        by_host = {tuple(_hosts(f)): f for f in findings}
        self.assertEqual(sorted(by_host), [("host-a.example.test",), ("host-b.example.test",)], by_host)
        self.assertTrue(by_host["host-a.example.test",].false_p)
        newcomer = by_host["host-b.example.test",]
        self.assertFalse(newcomer.false_p)
        self.assertTrue(newcomer.active)

    def test_new_host_is_not_folded_into_a_risk_acceptance(self):
        test_id = self._import("host-a.example.test")
        (original,) = self._findings(test_id)
        self._suppress(original, risk_accepted=True)

        self._reimport(test_id, "host-a.example.test", "host-b.example.test")

        newcomer = [f for f in self._findings(test_id) if _hosts(f) == ["host-b.example.test"]]
        self.assertEqual(len(newcomer), 1)
        self.assertFalse(newcomer[0].risk_accepted)
        self.assertTrue(newcomer[0].active)

    def test_suppressed_finding_still_matches_its_own_host(self):
        test_id = self._import("host-a.example.test")
        (original,) = self._findings(test_id)
        self._suppress(original, false_p=True)

        self._reimport(test_id, "host-a.example.test")

        findings = self._findings(test_id)
        self.assertEqual([f.id for f in findings], [original.id])
        self.assertTrue(findings[0].false_p)

    # ---- unsuppressed findings behave as before ---------------------------------------------

    def test_open_finding_still_collects_new_hosts(self):
        test_id = self._import("host-a.example.test")
        (original,) = self._findings(test_id)

        self._reimport(test_id, "host-a.example.test", "host-b.example.test")

        findings = self._findings(test_id)
        self.assertEqual([f.id for f in findings], [original.id])
        self.assertEqual(_hosts(findings[0]), ["host-a.example.test", "host-b.example.test"])

    # ---- each host's finding matches itself -------------------------------------------------

    def test_report_matches_the_finding_that_has_its_host(self):
        test_id = self._import("host-a.example.test", "host-b.example.test")
        first, second = self._findings(test_id)
        self.assertEqual(_hosts(first), ["host-a.example.test"])
        self.assertEqual(_hosts(second), ["host-b.example.test"])

        # Only host B still reports the issue: host B's finding stays open, host A's is closed.
        self._reimport(test_id, "host-b.example.test")

        first.refresh_from_db()
        second.refresh_from_db()
        self.assertTrue(second.active)
        self.assertFalse(second.is_mitigated)
        self.assertTrue(first.is_mitigated)
        self.assertEqual(_hosts(first), ["host-a.example.test"])
