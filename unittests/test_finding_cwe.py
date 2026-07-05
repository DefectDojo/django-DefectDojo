"""CWE-as-a-separate-relationship (Finding_CWE) and the API."""
from django.test import SimpleTestCase, override_settings
from rest_framework.authtoken.models import Token
from rest_framework.test import APIClient

from dojo.finding.helper import save_cwes
from dojo.finding.vulnerability_id import (
    cwe_label,
    cwe_number,
    finding_cwe_labels,
    parse_cwes,
)
from dojo.models import Finding, Finding_CWE, User
from unittests.dojo_test_case import DojoAPITestCase, DojoTestCase, versioned_fixtures


class TestCweHelpers(SimpleTestCase):

    def test_cwe_number(self):
        self.assertEqual(cwe_number("CWE-79"), 79)
        self.assertEqual(cwe_number("cwe-79"), 79)
        self.assertEqual(cwe_number("79"), 79)
        self.assertEqual(cwe_number(79), 79)
        self.assertIsNone(cwe_number("foo"))
        self.assertIsNone(cwe_number("CWE-"))
        self.assertIsNone(cwe_number(None))
        # 0 is Finding.cwe's "unset" sentinel, not a real CWE
        self.assertIsNone(cwe_number(0))
        self.assertIsNone(cwe_number("CWE-0"))

    def test_cwe_label(self):
        self.assertEqual(cwe_label("CWE-79"), "CWE-79")
        self.assertEqual(cwe_label("cwe-79"), "CWE-79")
        self.assertEqual(cwe_label("79"), "CWE-79")
        self.assertEqual(cwe_label(79), "CWE-79")
        self.assertIsNone(cwe_label("foo"))
        self.assertIsNone(cwe_label(None))

    def test_parse_cwes(self):
        # canonical CWE-<n> labels, deduplicated, order preserved
        self.assertEqual(parse_cwes("79\n89\nCWE-22"), ["CWE-79", "CWE-89", "CWE-22"])
        self.assertEqual(parse_cwes("79, 89"), ["CWE-79", "CWE-89"])
        self.assertEqual(parse_cwes("cwe-79"), ["CWE-79"])
        self.assertEqual(parse_cwes("not-a-cwe\n89"), ["CWE-89"])
        self.assertEqual(parse_cwes("79\nCWE-79\n79"), ["CWE-79"])
        self.assertEqual(parse_cwes(""), [])
        self.assertEqual(parse_cwes(None), [])

    def test_finding_cwe_labels(self):
        # primary first, extras appended, mixed int/str input normalized, deduplicated
        self.assertEqual(finding_cwe_labels(79, ["CWE-89", 89, "22"]), ["CWE-79", "CWE-89", "CWE-22"])
        self.assertEqual(finding_cwe_labels(0, [89]), ["CWE-89"])
        self.assertEqual(finding_cwe_labels(None, None), [])


@versioned_fixtures
class TestFindingCwe(DojoTestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = Finding.objects.get(id=2)
        Finding_CWE.objects.filter(finding=self.finding).delete()

    def _stored_cwes(self):
        return set(Finding_CWE.objects.filter(finding=self.finding).values_list("cwe", flat=True))

    def test_primary_cwe_saved_and_exposed(self):
        self.finding.cwe = 79
        save_cwes(self.finding)
        # stored as canonical CWE-<n> strings (mirrors vulnerability_ids)
        self.assertEqual(self._stored_cwes(), {"CWE-79"})
        self.assertEqual(Finding.objects.get(id=2).cwes, ["CWE-79"])

    def test_multiple_cwes(self):
        self.finding.cwe = 79
        self.finding.unsaved_cwes = [89, 89, 22]  # includes a duplicate
        save_cwes(self.finding)
        self.assertEqual(self._stored_cwes(), {"CWE-79", "CWE-89", "CWE-22"})
        # primary first, deduplicated, CWE-<n> form
        self.assertEqual(Finding.objects.get(id=2).cwes, ["CWE-79", "CWE-89", "CWE-22"])

    def test_no_cwe_stores_nothing(self):
        self.finding.cwe = 0
        save_cwes(self.finding)
        self.assertEqual(self._stored_cwes(), set())
        self.assertEqual(Finding.objects.get(id=2).cwes, [])

    def test_copy_finding_copies_cwes(self):
        self.finding.cwe = 79
        self.finding.unsaved_cwes = [89]
        save_cwes(self.finding)
        copy = self.finding.copy()
        self.assertEqual({"CWE-79", "CWE-89"}, set(copy.finding_cwe_set.values_list("cwe", flat=True)))


@versioned_fixtures
class TestFindingCwesAPI(DojoAPITestCase):
    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        super().setUp()
        self.system_settings(enable_jira=True)
        self.testuser = User.objects.get(username="admin")
        self.testuser.usercontactinfo.block_execution = True
        self.testuser.usercontactinfo.save()
        token = Token.objects.get(user=self.testuser)
        self.client = APIClient()
        self.client.credentials(HTTP_AUTHORIZATION="Token " + token.key)
        self.client.force_login(self.get_test_admin())

    def test_finding_create_with_cwes(self):
        # cwes mirror vulnerability_ids: nested [{"cwe": "CWE-79"}], first is the primary Finding.cwe
        finding_details = self.get_finding_api(2)
        del finding_details["id"]
        finding_details.pop("cve", None)
        finding_details.pop("cwe", None)
        new_cwes = [{"cwe": "CWE-79"}, {"cwe": "CWE-89"}]
        finding_details["cwes"] = new_cwes
        response = self.post_new_finding_api(finding_details)
        # response echoes the CWEs in CWE-<n> form
        self.assertEqual({"CWE-79", "CWE-89"}, {entry["cwe"] for entry in response.get("cwes")})
        finding = Finding.objects.get(id=response.get("id"))
        # primary cwe (legacy int) set from the first entry; both stored as canonical Finding_CWE rows
        self.assertEqual(79, finding.cwe)
        self.assertEqual({"CWE-79", "CWE-89"}, set(finding.finding_cwe_set.values_list("cwe", flat=True)))


@versioned_fixtures
class TestFindingCweHashCode(DojoTestCase):

    """get_cwes() and its use in compute_hash_code, incl. the unsaved_cwes import path."""

    fixtures = ["dojo_testdata.json"]

    def setUp(self):
        self.finding = Finding.objects.get(id=2)
        Finding_CWE.objects.filter(finding=self.finding).delete()

    def test_get_cwes_prefers_unsaved_cwes(self):
        # Extra CWE rows are not written yet; get_cwes must still reflect them via unsaved_cwes.
        self.finding.cwe = 79
        self.finding.unsaved_cwes = [89, 22]
        self.assertEqual(self.finding.get_cwes(), "".join(sorted(["CWE-79", "CWE-89", "CWE-22"])))

    def test_get_cwes_stable_before_and_after_save(self):
        # The pre-save (unsaved_cwes) and post-save (finding_cwe_set) hashes must agree.
        self.finding.cwe = 79
        self.finding.unsaved_cwes = [89, 22]
        before = self.finding.get_cwes()
        save_cwes(self.finding)
        reloaded = Finding.objects.get(id=2)  # unsaved_cwes is None on a fresh load
        self.assertEqual(before, reloaded.get_cwes())
        self.assertEqual(reloaded.get_cwes(), "".join(sorted(["CWE-79", "CWE-89", "CWE-22"])))

    def test_get_cwes_empty_when_no_cwe(self):
        self.finding.cwe = 0
        self.finding.unsaved_cwes = None
        save_cwes(self.finding)
        self.assertEqual(Finding.objects.get(id=2).get_cwes(), "")

    def test_compute_hash_code_uses_cwe_set(self):
        self.finding.cwe = 79
        scanner = self.finding.test.test_type.name
        # FINDING_COMPUTE_HASH_METHOD=None forces the OSS compute_hash_code path under test
        # (a Pro deployment would otherwise delegate to its tuner-driven hash method).
        with override_settings(
            FINDING_COMPUTE_HASH_METHOD=None,
            HASHCODE_FIELDS_PER_SCANNER={scanner: ["title", "cwes"]},
        ):
            self.finding.unsaved_cwes = [89]
            hash_with_89 = self.finding.compute_hash_code()
            self.finding.unsaved_cwes = [22]
            hash_with_22 = self.finding.compute_hash_code()
        # Different CWE set -> different hash, so cwes participates in the hash.
        self.assertNotEqual(hash_with_89, hash_with_22)
