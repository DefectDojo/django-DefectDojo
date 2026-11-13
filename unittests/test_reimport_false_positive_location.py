"""
Regression tests: a false-positive decision stays with its host, and reimport never closes a finding it still reports.

Many network scanners build the hash from the title, severity and vulnerability ids alone, so one
issue reported on several hosts shares one hash_code. False-positive history matched on that hash
alone, so marking the issue false positive on one host also marked every other host that reported
it, both on import and retroactively. It now compares locations the way deduplication does.

Reimport also closed a still-reported finding marked false positive or out of scope: when the
incoming finding did not carry the same status, the matched finding was left out of the findings
the report still contains, and close_old_findings mitigated it.
"""
import itertools
import json
import tempfile
from pathlib import Path

import hyperlink
from crum import impersonate
from django.test import SimpleTestCase, override_settings
from parameterized import parameterized

from dojo.finding.deduplication import (
    are_location_urls_equal,
    are_urls_equal,
    do_false_positive_history,
    url_match_key,
)
from dojo.models import Finding, Test, User
from dojo.url.models import URL
from unittests.dojo_test_case import DojoAPITestCase, versioned_fixtures

SCAN_TYPE = "Generic Findings Import"


def _finding(host):
    # Plugin text, as network scanners write it: it names the flaw, not the host. So the
    # hash_code is the same for every host.
    return {
        "title": "SMB Signing not required",
        "severity": "Medium",
        "cwe": 287,
        "description": "Signing is not required on the remote SMB server.",
        "static_finding": False,
        "dynamic_finding": True,
        "endpoints": [f"{host}:445"],
    }


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class FalsePositiveHistoryLocationTest(DojoAPITestCase):

    # Regression: false-positive history marked another host's finding false positive on a shared hash_code.

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        admin = User.objects.get(username="admin")
        # Post-processing (false-positive history included) runs in the request, not in a worker.
        admin.usercontactinfo.block_execution = True
        admin.usercontactinfo.save()
        self.login_as_admin()
        # False-positive history only runs with deduplication off.
        self.system_settings(
            enable_deduplication=False, false_positive_history=True, retroactive_false_positive_history=True,
        )
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _scan(self, *hosts):
        path = Path(self.tmp.name) / f"scan-{len(list(Path(self.tmp.name).iterdir()))}.json"
        path.write_text(json.dumps({"findings": [_finding(h) for h in hosts]}), encoding="utf-8")
        return str(path)

    def _import(self, host):
        test_id = self.import_scan_with_params(self._scan(host), scan_type=SCAN_TYPE, minimum_severity="Info")["test"]
        (finding,) = Finding.objects.filter(test=Test.objects.get(id=test_id))
        return finding

    @parameterized.expand([
        ("host-b.example.test", False),
        ("host-a.example.test", True),
    ])
    def test_import_follows_false_positive_only_on_its_host(self, host, expected_false_p):
        decided = self._import("host-a.example.test")
        Finding.objects.filter(pk=decided.pk).update(false_p=True, active=False, verified=False)

        incoming = self._import(host)

        incoming.refresh_from_db()
        self.assertEqual(incoming.hash_code, decided.hash_code)
        self.assertEqual(
            incoming.false_p, expected_false_p,
            msg=f"{host}: expected false_p={expected_false_p}, persisted={incoming.false_p}",
        )

    @parameterized.expand([
        ("host-b.example.test", False),
        ("host-a.example.test", True),
    ])
    def test_retroactive_history_follows_false_positive_only_on_its_host(self, host, expected_false_p):
        decided = self._import("host-a.example.test")
        other = self._import(host)
        self.assertFalse(Finding.objects.get(pk=other.pk).false_p)

        # What marking the finding false positive in the UI runs.
        Finding.objects.filter(pk=decided.pk).update(false_p=True, active=False, verified=False)
        with impersonate(User.objects.get(username="admin")):
            do_false_positive_history(Finding.objects.get(pk=decided.pk))

        other.refresh_from_db()
        self.assertEqual(
            other.false_p, expected_false_p,
            msg=f"{host}: expected false_p={expected_false_p}, persisted={other.false_p}",
        )
        self.assertEqual(other.active, not expected_false_p)


@versioned_fixtures
@override_settings(SECURE_SSL_REDIRECT=False)
class ReimportStillReportedSuppressedFindingTest(DojoAPITestCase):

    # Regression: reimport mitigated a still-reported false-positive or out-of-scope finding.

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.login_as_admin()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _scan(self, name, *hosts):
        path = Path(self.tmp.name) / f"{name}.json"
        path.write_text(json.dumps({"findings": [_finding(h) for h in hosts]}), encoding="utf-8")
        return str(path)

    @parameterized.expand([
        ("false_p",),
        ("out_of_scope",),
        ("risk_accepted",),
    ])
    def test_still_reported_suppressed_finding_is_not_mitigated(self, status_field):
        status = {status_field: True}
        test_id = self.import_scan_with_params(
            self._scan("import", "host-a.example.test", "host-b.example.test"), scan_type=SCAN_TYPE, minimum_severity="Info",
        )["test"]
        suppressed, gone = Finding.objects.filter(test_id=test_id).order_by("id")
        # The state a bulk update leaves, as false-positive history does: a save() would also have
        # marked the finding mitigated (update_finding_status), and close_old_findings skips those.
        Finding.objects.filter(pk=suppressed.pk).update(active=False, **status)

        # The report still has host A; host B is gone.
        self.reimport_scan_with_params(
            test_id, self._scan("reimport", "host-a.example.test"), scan_type=SCAN_TYPE, minimum_severity="Info",
            close_old_findings=True,
        )

        suppressed.refresh_from_db()
        gone.refresh_from_db()
        self.assertFalse(
            suppressed.is_mitigated,
            msg=f"{status}: still reported, persisted is_mitigated={suppressed.is_mitigated} mitigated={suppressed.mitigated}",
        )
        self.assertIsNone(suppressed.mitigated)
        for field, value in status.items():
            self.assertEqual(getattr(suppressed, field), value)
        self.assertFalse(suppressed.active)
        # Control: the finding the report no longer has is closed as before.
        self.assertTrue(gone.is_mitigated, msg=f"persisted is_mitigated={gone.is_mitigated}")


class LocationMatchKeyTest(SimpleTestCase):

    # False-positive history compares locations by key; a key must agree with the equality it stands in for.

    ENDPOINTS = [
        "https://host-a.example.com/app?q=1#top",
        "https://host-a.example.com:8443/app?q=1#top",
        "http://host-a.example.com/app?q=1#top",
        "https://host-b.example.com/app?q=1#top",
        "https://host-a.example.com/other?q=2",
        "https://user:secret@example.com/app",
        "https://other:secret@example.com/app",
        "//host-a.example.com:445",
    ]
    LOCATIONS = [
        {"protocol": "https", "host": "host-a.example.test", "port": 443, "path": "app", "query": "q=1", "fragment": "top"},
        {"protocol": "https", "host": "host-a.example.test", "port": 8443, "path": "app", "query": "q=1", "fragment": "top"},
        {"protocol": "http", "host": "host-a.example.test", "port": 80, "path": "app", "query": "q=1", "fragment": "top"},
        {"protocol": "https", "host": "host-b.example.test", "port": 443, "path": "app", "query": "q=1", "fragment": "top"},
        {"protocol": "https", "host": "host-a.example.test", "port": 443, "path": "other", "query": "q=2"},
        {"protocol": "https", "host": "host-a.example.test", "port": 443, "path": "app", "user_info": "user"},
        {"protocol": "https", "host": "host-a.example.test", "port": 443, "path": "app", "user_info": "other"},
    ]
    FIELD_SETS = [
        ["host", "path"],
        ["host"],
        ["scheme", "host", "port", "path", "query", "fragment", "userinfo", "user"],
        ["port"],
        ["not_a_field"],
    ]

    def _assert_keys_agree(self, urls, equal):
        for fields in self.FIELD_SETS:
            for first, second in itertools.product(urls, repeat=2):
                self.assertEqual(
                    url_match_key(first, equal, fields) == url_match_key(second, equal, fields),
                    equal(first, second, fields),
                    msg=f"{fields}: {first} / {second}",
                )

    def test_endpoint_keys_agree_with_are_urls_equal(self):
        self._assert_keys_agree([hyperlink.parse(url) for url in self.ENDPOINTS], are_urls_equal)

    def test_location_keys_agree_with_are_location_urls_equal(self):
        self._assert_keys_agree([URL(**fields) for fields in self.LOCATIONS], are_location_urls_equal)
