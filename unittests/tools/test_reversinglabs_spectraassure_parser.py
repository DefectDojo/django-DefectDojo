# ruff: noqa: RUF100
# ruff: noqa: I001
import io
import json
from collections.abc import Callable
from typing import Any

from dojo.models import Finding, Test
from dojo.tools.reversinglabs_spectraassure.parser import ReversinglabsSpectraassureParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path, skip_unless_v3

"""
run with:

./run-unittest.sh --test-case
    unittests.tools.test_reversinglabs_spectraassure_parser.TestReversingLabsSpectraAssureParser

FD13-FullUSB.zip:       no CVE; two 'threats' and one 'secrets' policy violation
putty_win_x64-0.80.exe: one CVE, no policy violation findings
HxDSetup_2.5.0.exe:     two executables, each in 18 language builds: same name and path, different sha256,
                        so different binaries and separate findings
azure-cli-2.84.0-x64:   many CVE plus one 'secrets' violation that carries secret detail;
                        the only fixture whose CVE findings carry a purl, so it covers Locations
synthetic-shared-component: hand-built, NOT a scanner output. One component carrying a CVE and
                        two violations per category, in a report whose info.file has no sha256,
                        plus the same binary (same sha256) at a second path.

"""

_WHERE = "reversinglabs_spectraassure"


# mypy gives:  error: Class cannot subclass "DojoTestCase" (has type "Any")  [misc]
class TestReversingLabsSpectraAssureParser(DojoTestCase):  # type: ignore[misc]
    def common_checks(self, finding: Finding) -> None:
        self.assertTrue(finding.title)
        self.assertLessEqual(len(finding.title), 250)
        self.assertNotIn("  ", finding.title)  # no collapsed-empty parts in the joined title

        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)

        self.assertEqual(True, finding.static_finding)  # by specification
        self.assertEqual(False, finding.dynamic_finding)  # by specification

        self.assertIsNotNone(finding.date)
        self.assertTrue(finding.vuln_id_from_tool)

        # the description opens with the title as a markdown heading: '#' needs the space
        self.assertTrue(finding.description.startswith(f"# {finding.title}\n"))
        # merging a repeat must not append the whole description again
        self.assertEqual(1, finding.description.count(f"# {finding.title}"))

        # the dedupe identity (HASHCODE_FIELDS_PER_SCANNER): what was found, in which component file;
        # the parser itself never sets hash_code, DefectDojo computes it from the settings
        self.assertTrue(finding.unique_id_from_tool.startswith(f"{finding.vuln_id_from_tool}/"))
        self.assertIsNone(getattr(finding, "hash_code", None))
        # hash_code fields: never an empty string (DefectDojo stores blank as NULL after hashing)
        self.assertNotEqual("", finding.component_name)
        self.assertNotEqual("", finding.component_version)

    def split_cve_and_violation(
        self,
        findings: list[Finding],
    ) -> tuple[list[Finding], list[Finding]]:
        # CVE findings carry a vulnerability id; policy violation findings never do
        cves = [f for f in findings if f.unsaved_vulnerability_ids]
        violations = [f for f in findings if not f.unsaved_vulnerability_ids]

        for f in cves:
            self.assertEqual(1, len(f.unsaved_vulnerability_ids))
            self.assertTrue(
                f.unsaved_vulnerability_ids[0].startswith(("CVE-", "GHSA-")),
            )

        for f in violations:
            # <category>-<rule_id>, e.g. 'secrets-SQ34201'
            self.assertIn("-", f.vuln_id_from_tool)
            self.assertIsNone(f.cvssv3_score)
            self.assertIsNone(f.cvssv4_score)

        return cves, violations

    def rule_ids(self, findings: list[Finding], category: str) -> set[str]:
        return {f.vuln_id_from_tool for f in findings if f.vuln_id_from_tool.startswith(f"{category}-")}

    def severity_counts(self, findings: list[Finding]) -> dict[str, int]:
        # pins the CVSS score -> severity mapping, which nothing else asserts
        counts: dict[str, int] = {}
        for finding in findings:
            counts[finding.severity] = counts.get(finding.severity, 0) + 1
        return counts

    def test_parse_file_with_no_vuln(self) -> None:
        # no CVE: two 'threats' violations (malware) and one 'secrets' violation
        with (get_unit_tests_scans_path(_WHERE) / "FD13-FullUSB.zip-report.rl.json").open(encoding="utf-8") as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(3, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(0, len(cves))
            self.assertEqual(3, len(violations))

            self.assertEqual({"threats-SQ30110", "threats-SQ30108"}, self.rule_ids(violations, "threats"))
            self.assertEqual({"secrets-SQ34201"}, self.rule_ids(violations, "secrets"))
            self.assertEqual({"High": 3}, self.severity_counts(findings))

            # a violation carries the version of its component; these files report "Generic" without a purl: no version
            self.assertEqual({None}, {f.component_version for f in violations})

    def test_parse_file_with_one_vuln(self) -> None:
        with (get_unit_tests_scans_path(_WHERE) / "putty_win_x64-0.80.exe-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(1, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(1, len(cves))
            self.assertEqual(0, len(violations))
            self.assertEqual("CVE-2024-31497", cves[0].vuln_id_from_tool)
            self.assertEqual({"Medium": 1}, self.severity_counts(findings))

    def test_parse_file_with_many_vulns(self) -> None:
        # --------------------------------------
        with (get_unit_tests_scans_path(_WHERE) / "HxDSetup_2.5.0.exe-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            # 6 CVE x 2 executables x 18 language builds
            self.assertEqual(216, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(216, len(cves))
            self.assertEqual(0, len(violations))

            self.assertEqual({"Critical": 108, "High": 108}, self.severity_counts(findings))

            # same name and same path, but a different sha256 is a different binary: every build is its own
            # finding, with its own dedupe identity, and a title that tells it apart from its 17 siblings
            self.assertEqual(216, len({f.unique_id_from_tool for f in findings}))
            self.assertEqual(216, len({f.title for f in findings}))

            hxd64 = [
                f for f in findings if f.vuln_id_from_tool == "CVE-2016-9840" and f.file_path.endswith("/HxD64.exe")
            ]
            self.assertEqual(18, len(hxd64))
            self.assertEqual({"zlib"}, {f.component_name for f in hxd64})
            self.assertEqual({1}, {f.nb_occurences for f in hxd64})

    def test_parse_file_with_secrets(self) -> None:
        # many CVE plus one 'secrets' violation whose description carries the secret detail
        with (get_unit_tests_scans_path(_WHERE) / "azure-cli-2.84.0-x64-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(105, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(104, len(cves))
            self.assertEqual(1, len(violations))

            self.assertEqual({"Critical": 2, "High": 50, "Low": 19, "Medium": 34}, self.severity_counts(findings))

            secret = violations[0]
            self.assertEqual("secrets-SQ34304", secret.vuln_id_from_tool)
            self.assertEqual("High", secret.severity)

            # the secret detail is rendered as a fenced block by RlJsonInfo
            self.assertIn("```", secret.description)
            self.assertIn("service: ", secret.description)
            self.assertIn("liveness: ", secret.description)
            self.assertIn("exposed: ", secret.description)

    def test_cvss_v4_scores(self) -> None:
        # azure-cli has CVSS v3 and v4 vulnerabilities: each score goes to the field of its own version, never both
        with (get_unit_tests_scans_path(_WHERE) / "azure-cli-2.84.0-x64-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            v3 = [f for f in findings if f.cvssv3_score is not None]
            v4 = [f for f in findings if f.cvssv4_score is not None]
            self.assertEqual(77, len(v3))
            self.assertEqual(27, len(v4))
            self.assertEqual([], [f for f in v4 if f.cvssv3_score is not None])

            # the report score is used as is: for this CVE it includes the v4 threat metric (exploit unproven),
            # which the base metrics alone would score 6.3 (Medium)
            finding = next(f for f in findings if f.vuln_id_from_tool == "CVE-2026-27448")
            self.assertIsNone(finding.cvssv3_score)
            self.assertEqual(1.7, finding.cvssv4_score)
            self.assertEqual("Low", finding.severity)

    def test_parse_file_with_shared_component(self) -> None:
        # Synthetic fixture, hand-built. Covers what no real sample does:
        #  - several violations on the SAME component must stay separate findings: results are
        #    keyed on <category>-<rule_id>; keying on None collapsed them into one, silently.
        #    Two per category, so either collector regressing on its own is caught.
        #  - report.info.file has no sha256: that used to abort the whole import, on both the
        #    CVE path and the violation path, so the fixture carries one of each.
        #  - CVSS version "3.1" rather than the "3" every real sample has.
        with (get_unit_tests_scans_path(_WHERE) / "synthetic-shared-component-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.assertEqual(5, len(findings))
            for finding in findings:
                self.common_checks(finding)

            cves, violations = self.split_cve_and_violation(findings)
            self.assertEqual(1, len(cves))
            self.assertEqual(4, len(violations))

            self.assertEqual({"threats-SQ30110", "threats-SQ30108"}, self.rule_ids(violations, "threats"))
            self.assertEqual({"secrets-SQ34304", "secrets-SQ34101"}, self.rule_ids(violations, "secrets"))
            self.assertEqual({"Critical": 2, "High": 1, "Medium": 1, "Low": 1}, self.severity_counts(findings))

            # everything sits on the one component
            self.assertEqual({"payload.dll"}, {f.component_name for f in findings})
            self.assertEqual({"1.0"}, {f.component_version for f in findings})  # violations too
            self.assertEqual({"synthetic-installer.exe/payload.dll"}, {f.file_path for f in findings})

            # the same binary (same sha256) also sits at a second path: one finding, counted twice,
            # with the second location noted rather than the whole description repeated
            self.assertEqual({1}, {f.nb_occurences for f in violations})

            threat = next(f for f in violations if f.vuln_id_from_tool == "threats-SQ30110")
            self.assertIn("Threat name: Win32.Trojan.Synthetic", threat.description)

            cve = cves[0]
            self.assertEqual("CVE-2099-0001", cve.vuln_id_from_tool)
            self.assertEqual(9.8, cve.cvssv3_score)  # version "3.1" routes to the v3 field
            self.assertIsNone(cve.cvssv4_score)
            self.assertEqual(["Fix Available"], cve.unsaved_tags)
            self.assertEqual(2, cve.nb_occurences)
            self.assertIn("- also at: synthetic-installer.exe/backup/payload.dll", cve.description)

    # --------------------------------------------
    # Variants of the synthetic fixture, changed in memory: each covers one rule no real sample exercises.

    _COMP = "5b1f8a52-0c3e-5d7a-9e44-2f6b0a1c9d37"  # payload.dll; carries all four violations
    _COMP_BACKUP = "9d4e7b21-3a8c-5f60-b1d2-6e0c8a4f7b93"  # the same binary at a second path

    def parse_synthetic_variant(self, change: Callable[[dict[str, Any]], None]) -> list[Finding]:
        with (get_unit_tests_scans_path(_WHERE) / "synthetic-shared-component-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            data = json.load(testfile)

        change(data)
        variant = io.StringIO(json.dumps(data))
        variant.name = "synthetic-variant.rl.json"  # RlJsonInfo logs the file name
        findings: list[Finding] = ReversinglabsSpectraassureParser().get_findings(variant, Test())
        return findings

    def synthetic_cve(self, findings: list[Finding]) -> Finding:
        return next(f for f in findings if f.vuln_id_from_tool == "CVE-2099-0001")

    def test_report_without_valid_timestamp_is_rejected(self) -> None:
        # the timestamp is the date of every finding: without it the import fails rather than dating findings 'today'
        with self.assertRaisesRegex(ValueError, "Missing 'timestamp'"):
            self.parse_synthetic_variant(lambda data: data.pop("timestamp"))

        with self.assertRaisesRegex(ValueError, "Invalid 'timestamp'"):
            self.parse_synthetic_variant(lambda data: data.update(timestamp="yesterday"))

    def test_dependency_description_without_purl_names_the_component_as_item(self) -> None:
        # a dependency finding describes the component the dependency was found in:
        # by its purl, or without one as 'item: <name> <version>'
        def add_dependency(component_purl: str) -> Callable[[dict[str, Any]], None]:
            def change(data: dict[str, Any]) -> None:
                metadata = data["report"]["metadata"]
                metadata["dependencies"] = {
                    "dep-1": {
                        "product": "zlib",
                        "version": "1.2.11",
                        "vulnerabilities": {"active": ["CVE-2099-0002"]},
                    },
                }
                metadata["vulnerabilities"]["CVE-2099-0002"] = {
                    "cvss": {"version": "3.1", "baseScore": 5.0},
                    "summary": "Synthetic dependency vulnerability.",
                }
                identity = metadata["components"][self._COMP]["identity"]
                identity["dependencies"] = ["dep-1"]
                identity["purl"] = component_purl

            return change

        dep = next(
            f for f in self.parse_synthetic_variant(add_dependency("")) if f.vuln_id_from_tool == "CVE-2099-0002"
        )
        self.common_checks(dep)
        self.assertIn(" on dependency: ", dep.title)
        self.assertEqual("zlib", dep.component_name)
        self.assertIn("**item: payload.dll 1.0**", dep.description)
        self.assertNotIn("**purl: ", dep.description)

        dep = next(
            f
            for f in self.parse_synthetic_variant(add_dependency("pkg:generic/payload@1.0"))
            if f.vuln_id_from_tool == "CVE-2099-0002"
        )
        self.assertIn("**purl: pkg:generic/payload@1.0**", dep.description)
        self.assertNotIn("**item: ", dep.description)

    def test_component_description_without_purl_names_the_component_as_item(self) -> None:
        # a vulnerability on the component itself: by its purl (plus the version), or without one by its name
        def set_identity(purl: str, name: str) -> Callable[[dict[str, Any]], None]:
            def change(data: dict[str, Any]) -> None:
                for comp_uuid in (self._COMP, self._COMP_BACKUP):
                    component = data["report"]["metadata"]["components"][comp_uuid]
                    component["identity"]["purl"] = purl
                    component["name"] = name

            return change

        cve = self.synthetic_cve(self.parse_synthetic_variant(set_identity("", "payload.dll")))
        self.assertIn("**item: payload.dll 1.0**", cve.description)
        self.assertNotIn("- version ", cve.description)

        cve = self.synthetic_cve(self.parse_synthetic_variant(set_identity("pkg:generic/payload@1.0", "payload.dll")))
        self.assertIn("**purl: pkg:generic/payload@1.0**", cve.description)
        self.assertIn("- version 1.0", cve.description)
        self.assertNotIn("**item: ", cve.description)

        # no name: nothing to show as item, the version stays
        cve = self.synthetic_cve(self.parse_synthetic_variant(set_identity("", "")))
        self.common_checks(cve)
        self.assertNotIn("**item: ", cve.description)
        self.assertIn("- version 1.0", cve.description)

    def test_empty_version_is_left_out_of_title_and_item(self) -> None:
        def change(data: dict[str, Any]) -> None:
            for comp_uuid in (self._COMP, self._COMP_BACKUP):
                component = data["report"]["metadata"]["components"][comp_uuid]
                component["identity"]["version"] = ""
                component["hashes"] = []  # no sha256 either: the title must not end in a space

        findings = self.parse_synthetic_variant(change)
        for finding in findings:
            self.common_checks(finding)
            self.assertFalse(finding.title.endswith(" "))

        cve = self.synthetic_cve(findings)
        self.assertEqual("CVE-2099-0001 on component: payload.dll", cve.title)
        self.assertIn("**item: payload.dll**", cve.description)

    def test_generic_version_without_purl_is_no_version(self) -> None:
        # Spectra Assure reports "Generic" for a file without a version of its own; without a purl that is no version
        def generic(purl: str) -> Callable[[dict[str, Any]], None]:
            def change(data: dict[str, Any]) -> None:
                for comp_uuid in (self._COMP, self._COMP_BACKUP):
                    identity = data["report"]["metadata"]["components"][comp_uuid]["identity"]
                    identity["version"] = "Generic"
                    identity["purl"] = purl

            return change

        findings = self.parse_synthetic_variant(generic(""))
        for finding in findings:
            self.common_checks(finding)
            self.assertIsNone(finding.component_version, finding.title)  # the CVE and the four violations
            self.assertNotIn("Generic", finding.title)
            self.assertNotIn("Generic", finding.description)
        cve = self.synthetic_cve(findings)
        self.assertEqual("CVE-2099-0001 on component: payload.dll (sha256 11111111)", cve.title)
        self.assertIn("**item: payload.dll**", cve.description)

        # with a purl it is the package version as reported, kept
        findings = self.parse_synthetic_variant(generic("pkg:generic/payload.dll@Generic"))
        self.assertEqual({"Generic"}, {f.component_version for f in findings})

    def test_title_formats(self) -> None:
        # the exact title of each kind of finding, with and without a purl
        def change(component_purl: str, dependency_purl: str) -> Callable[[dict[str, Any]], None]:
            def apply(data: dict[str, Any]) -> None:
                metadata = data["report"]["metadata"]
                metadata["dependencies"] = {
                    "dep-1": {
                        "product": "zlib",
                        "version": "1.2.11",
                        "purl": dependency_purl,
                        "vulnerabilities": {"active": ["CVE-2099-0002"]},
                    },
                }
                metadata["vulnerabilities"]["CVE-2099-0002"] = {"cvss": {"version": "3.1", "baseScore": 5.0}}
                for comp_uuid in (self._COMP, self._COMP_BACKUP):
                    metadata["components"][comp_uuid]["identity"]["purl"] = component_purl
                metadata["components"][self._COMP]["identity"]["dependencies"] = ["dep-1"]

            return apply

        titles = {f.vuln_id_from_tool: f.title for f in self.parse_synthetic_variant(change("", ""))}
        self.assertEqual(
            "CVE-2099-0001 on component: payload.dll version 1.0 (sha256 11111111)",
            titles["CVE-2099-0001"],
        )
        self.assertEqual("CVE-2099-0002 on dependency: zlib version 1.2.11 (sha256 11111111)", titles["CVE-2099-0002"])
        self.assertEqual(
            "Detected presence of malicious files through file reputation or third-party scan. (threats)"
            " on payload.dll (sha256 11111111)",
            titles["threats-SQ30110"],
        )
        self.assertEqual(
            "Detected presence of web service access tokens. (secrets) on payload.dll (sha256 11111111)",
            titles["secrets-SQ34304"],
        )

        titles = {
            f.vuln_id_from_tool: f.title
            for f in self.parse_synthetic_variant(change("pkg:generic/payload@1.0", "pkg:generic/zlib@1.2.11"))
        }
        self.assertEqual(
            "CVE-2099-0001 on component: purl: pkg:generic/payload@1.0 (sha256 11111111)",
            titles["CVE-2099-0001"],
        )
        # a dependency is named by its own purl; the sha256 is that of the component it was found in
        self.assertEqual(
            "CVE-2099-0002 on dependency: purl: pkg:generic/zlib@1.2.11 (sha256 11111111)",
            titles["CVE-2099-0002"],
        )

    def test_missing_references_are_skipped(self) -> None:
        # dangling references in a report drop only what they point to, never the whole import
        def change(data: dict[str, Any]) -> None:
            metadata = data["report"]["metadata"]
            identity = metadata["components"][self._COMP]["identity"]
            identity["vulnerabilities"]["active"].append("CVE-2099-9999")  # not in metadata.vulnerabilities
            identity["dependencies"] = ["dep-missing"]  # not in metadata.dependencies
            metadata["violations"]["c0ffee00-0000-4000-8000-000000000000"] = {
                "status": "fail",
                "category": "threats",
                "rule_id": "SQ39999",
                "severity": "high",
                "description": "Synthetic violation on a component that is not in the report.",
                "references": {"component": ["comp-missing"]},
            }

        findings = self.parse_synthetic_variant(change)
        self.assertEqual(
            {"CVE-2099-0001", "threats-SQ30110", "threats-SQ30108", "secrets-SQ34304", "secrets-SQ34101"},
            {f.vuln_id_from_tool for f in findings},
        )

    def test_unproven_and_triaged_exploit_keys_are_ignored(self) -> None:
        def change(data: dict[str, Any]) -> None:
            data["report"]["metadata"]["vulnerabilities"]["CVE-2099-0001"]["exploit"] = ["UNPROVEN", "TRIAGED"]

        # an unknown key is skipped too, but with a 'missing tag' warning: ignored keys are known and stay silent
        with self.assertNoLogs("dojo.tools.reversinglabs_spectraassure", level="WARNING"):
            cve = self.synthetic_cve(self.parse_synthetic_variant(change))
        self.assertEqual([], cve.unsaved_tags)
        self.assertFalse(cve.impact)
        self.assertFalse(cve.known_exploited)

    def test_patching_mandated_sets_known_exploited(self) -> None:
        def change(data: dict[str, Any]) -> None:
            data["report"]["metadata"]["vulnerabilities"]["CVE-2099-0001"]["exploit"] = [
                "MANDATE",
                "EXISTS",
                "FIXABLE",
                "MALWARE",
            ]

        cve = self.synthetic_cve(self.parse_synthetic_variant(change))
        self.assertTrue(cve.known_exploited)
        self.assertEqual(
            {"Fix Available", "Exploit Exists", "Exploited by Malware", "Patching Mandated"},
            set(cve.unsaved_tags),
        )
        # impact lines follow the Portal order, whatever the order in the report
        self.assertEqual("Fix Available\nExploit Exists\nExploited by Malware\nPatching Mandated\n", cve.impact)

    def test_unknown_violation_severity_becomes_info(self) -> None:
        def change(data: dict[str, Any]) -> None:
            data["report"]["metadata"]["violations"]["b2d8f3a6-4c1e-4b7d-a5f0-1e9c6d3b8a27"]["severity"] = "bogus"

        findings = self.parse_synthetic_variant(change)
        severities = {f.vuln_id_from_tool: f.severity for f in findings}
        self.assertEqual("Info", severities["threats-SQ30108"])
        self.assertEqual("Critical", severities["threats-SQ30110"])  # the others are untouched

    def test_unique_id_falls_back_to_path_without_sha256(self) -> None:
        def change(data: dict[str, Any]) -> None:
            for comp_uuid in (self._COMP, self._COMP_BACKUP):
                data["report"]["metadata"]["components"][comp_uuid]["hashes"] = []

        findings = self.parse_synthetic_variant(change)
        for finding in findings:
            self.common_checks(finding)
            self.assertNotIn("(sha256 ", finding.title)

        # without a sha256 nothing says the two paths hold the same binary: two CVE findings, not one merged
        self.assertEqual(6, len(findings))
        self.assertEqual(
            {
                "CVE-2099-0001/path:synthetic-installer.exe/payload.dll",
                "CVE-2099-0001/path:synthetic-installer.exe/backup/payload.dll",
            },
            {f.unique_id_from_tool for f in findings if f.vuln_id_from_tool == "CVE-2099-0001"},
        )
        self.assertEqual({1}, {f.nb_occurences for f in findings})
        self.assertEqual(
            "threats-SQ30110/path:synthetic-installer.exe/payload.dll",
            next(f.unique_id_from_tool for f in findings if f.vuln_id_from_tool == "threats-SQ30110"),
        )

    # mypy gives:  error: Untyped decorator makes function "test_dependency_locations" untyped  [untyped-decorator]
    @skip_unless_v3  # type: ignore[untyped-decorator]
    def test_dependency_locations(self) -> None:
        # with V3_FEATURE_LOCATIONS on, a CVE finding with a purl gets exactly one dependency
        # location for that package; findings without a purl, and violations, get none
        with (get_unit_tests_scans_path(_WHERE) / "azure-cli-2.84.0-x64-report.rl.json").open(
            encoding="utf-8",
        ) as testfile:
            parser = ReversinglabsSpectraassureParser()
            findings = parser.get_findings(testfile, Test())

            self.validate_locations(findings)

            with_location = [f for f in findings if f.unsaved_locations]
            self.assertEqual(71, len(with_location))

            for finding in findings:
                dependencies = [loc.data for loc in finding.unsaved_locations if loc.type == "dependency"]
                self.assertEqual(len(finding.unsaved_locations), len(dependencies))  # nothing but dependencies

                if not finding.unsaved_vulnerability_ids:
                    self.assertEqual([], dependencies)  # policy violations carry no package
                    continue

                if dependencies:
                    self.assertEqual(1, len(dependencies))
                    purl = dependencies[0]["purl"]
                    self.assertTrue(purl.startswith("pkg:"))
                    self.assertEqual(finding.file_path, dependencies[0]["file_path"])

                    if " on dependency:" in finding.title:
                        # the location names the vulnerable dependency, not the package containing it
                        # (e.g. requests inside requests-oauthlib). purl names are normalized, so lower()
                        expected = f"/{finding.component_name}@{finding.component_version}".lower()
                        self.assertIn(expected, purl.lower())

            requests = [
                loc.data
                for f in findings
                for loc in f.unsaved_locations
                if loc.data["purl"] == "pkg:pypi/requests@2.32.4?artifact_tag=py3-none-any"
            ]
            self.assertTrue(requests)
