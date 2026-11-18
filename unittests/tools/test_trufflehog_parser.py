
from django.test import override_settings

from dojo.models import Test
from dojo.tools.trufflehog.parser import TruffleHogParser, unique_id_from_tool
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


def sample_path(file_name):
    return get_unit_tests_scans_path("trufflehog") / file_name


# The unique id of the verified AWS key in the v3 fixtures. The same vector is pinned in the Go port
# (go-dojo-pro) and in the TruffleHog connector, so the three implementations are proven to agree.
AWS_FIXTURE_UNIQUE_ID = "97bfc698f6ac23fd237955c884ff4dc06a70a7571c2cd33202eee358709902fc"
AWS_FIXTURE_RAW = "QUtJQVlWUDRDSVBQRVJVVklGWEc="


class TestTruffleHogParser(DojoTestCase):

    def test_many_vulns_v2(self):
        with sample_path("v2_many_vulns.json").open(encoding="utf-8") as test_file:
            parser = TruffleHogParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 18)
            finding = findings[0]
            self.assertEqual("Medium", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("test_all.py", finding.file_path)

    def test_many_vulns_git_v3(self):
        with sample_path("v3_git.json").open(encoding="utf-8") as test_file:
            parser = TruffleHogParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("keys", finding.file_path)

    def test_many_vulns_github_v3(self):
        with sample_path("v3_github.json").open(encoding="utf-8") as test_file:
            parser = TruffleHogParser()
            findings = parser.get_findings(test_file, Test())
            self.assertEqual(len(findings), 3)
            finding = findings[0]
            self.assertEqual("Critical", finding.severity)
            self.assertEqual(798, finding.cwe)
            self.assertEqual("keys", finding.file_path)

    def test_v3_unique_id_is_stable_across_commits(self):
        """The same secret at the same path keeps its id whatever commit or line it is found at."""
        with sample_path("v3_git_repeated_commits.json").open(encoding="utf-8") as test_file:
            findings = TruffleHogParser().get_findings(test_file, Test())
        # One finding per commit by default: the fold key still carries the commit.
        self.assertEqual(len(findings), 4)
        same_file_commit_a, same_file_commit_b, other_file, rotated = findings
        self.assertEqual(same_file_commit_a.unique_id_from_tool, same_file_commit_b.unique_id_from_tool)
        self.assertEqual(4, same_file_commit_a.line)
        self.assertEqual(7, same_file_commit_b.line)
        # A copy of the secret in another file is another finding.
        self.assertNotEqual(same_file_commit_a.unique_id_from_tool, other_file.unique_id_from_tool)
        # A rotated secret at the same path is a new finding.
        self.assertNotEqual(same_file_commit_a.unique_id_from_tool, rotated.unique_id_from_tool)
        self.assertRegex(same_file_commit_a.unique_id_from_tool, r"^[0-9a-f]{64}$")
        self.assertNotIn(AWS_FIXTURE_RAW, same_file_commit_a.unique_id_from_tool)

    def test_v3_unique_id_matches_the_shared_vector(self):
        """The git and GitHub sources name the repository differently (.git suffix) and still agree."""
        for file_name in ("v3_git.json", "v3_github.json"):
            with self.subTest(file_name=file_name), sample_path(file_name).open(encoding="utf-8") as test_file:
                findings = TruffleHogParser().get_findings(test_file, Test())
                self.assertEqual(AWS_FIXTURE_UNIQUE_ID, findings[0].unique_id_from_tool)
                self.assertEqual(len(findings), len({finding.unique_id_from_tool for finding in findings}))
        self.assertEqual(
            AWS_FIXTURE_UNIQUE_ID,
            unique_id_from_tool("AWS", "https://github.com/trufflesecurity/test_keys.git/", "keys", AWS_FIXTURE_RAW),
        )

    def test_v3_unique_id_absent_without_secret_material(self):
        self.assertIsNone(unique_id_from_tool("AWS", "https://github.com/trufflesecurity/test_keys", "keys", ""))

    @override_settings(TRUFFLEHOG_FOLD_COMMITS=True)
    def test_v3_fold_commits_gives_one_finding_per_secret_per_file(self):
        with sample_path("v3_git_repeated_commits.json").open(encoding="utf-8") as test_file:
            findings = TruffleHogParser().get_findings(test_file, Test())
        self.assertEqual(len(findings), 3)
        folded, other_file, rotated = findings
        self.assertEqual(2, folded.nb_occurences)
        self.assertEqual(4, folded.line)
        self.assertIn("**Commit Hash:** fbc14303ffbf8fb1c2c1914e8dda7d0121633aca\n", folded.description)
        self.assertIn("**Commit Hash:** 77b2a3e56973785a52ba4ae4b8dac61d4bac016f\n", folded.description)
        self.assertEqual(1, other_file.nb_occurences)
        self.assertEqual(1, rotated.nb_occurences)
        self.assertEqual(3, len({finding.unique_id_from_tool for finding in findings}))

    def test_v2_has_no_unique_id(self):
        with sample_path("v2_many_vulns.json").open(encoding="utf-8") as test_file:
            findings = TruffleHogParser().get_findings(test_file, Test())
        self.assertEqual(len(findings), 18)
        self.assertTrue(all(finding.unique_id_from_tool is None for finding in findings))
