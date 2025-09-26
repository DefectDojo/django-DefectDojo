from django.test import TestCase

from dojo.tools.snyk_issue_api.parser import SnykIssueApiParser


class TestSnykIssueApiParser(TestCase):

    def test_extract_cwe_classes_single_cwe(self):
        parser = SnykIssueApiParser()
        attributes = {
            "classes": [
                {
                    "id": "CWE-400",
                    "source": "CWE",
                    "type": "weakness",
                },
            ],
        }
        cwes = parser.extract_cwe_classes(attributes)
        self.assertEqual([400], cwes)

    def test_extract_cwe_classes_multiple_cwes(self):
        parser = SnykIssueApiParser()
        attributes = {
            "classes": [
                {
                    "id": "CWE-259",
                    "source": "CWE",
                    "type": "weakness",
                },
                {
                    "id": "CWE-798",
                    "source": "CWE",
                    "type": "weakness",
                },
            ],
        }
        cwes = parser.extract_cwe_classes(attributes)
        self.assertEqual([259, 798], cwes)

    def test_extract_cwe_classes_no_cwes(self):
        parser = SnykIssueApiParser()
        attributes = {"classes": []}
        cwes = parser.extract_cwe_classes(attributes)
        self.assertEqual([], cwes)

    def test_extract_cwe_classes_non_cwe_source(self):
        parser = SnykIssueApiParser()
        attributes = {
            "classes": [
                {
                    "id": "OWASP-A1",
                    "source": "OWASP",
                    "type": "weakness",
                },
            ],
        }
        cwes = parser.extract_cwe_classes(attributes)
        self.assertEqual([], cwes)

    # Tests for extract_if_fix_is_available()
    def test_extract_if_fix_is_available_code_fixable(self):
        parser = SnykIssueApiParser()
        coordinates = [
            {
                "is_fixable_snyk": True,
                "is_fixable_upstream": False,
                "is_fixable_manually": False,
            },
        ]
        result = parser.extract_if_fix_is_available("code", coordinates)
        self.assertTrue(result)

    def test_extract_if_fix_is_available_code_not_fixable(self):
        parser = SnykIssueApiParser()
        coordinates = [
            {
                "is_fixable_snyk": False,
                "is_fixable_upstream": False,
                "is_fixable_manually": False,
            },
        ]
        result = parser.extract_if_fix_is_available("code", coordinates)
        self.assertFalse(result)

    def test_extract_if_fix_is_available_sca_upgradeable(self):
        parser = SnykIssueApiParser()
        coordinates = [
            {
                "is_fixable_snyk": False,
                "is_fixable_upstream": False,
                "is_fixable_manually": False,
                "is_patchable": False,
                "is_pinnable": False,
                "is_upgradeable": True,
            },
        ]
        result = parser.extract_if_fix_is_available("package_vulnerability", coordinates)
        self.assertTrue(result)

    def test_extract_if_fix_is_available_none_coordinates(self):
        parser = SnykIssueApiParser()
        result = parser.extract_if_fix_is_available("code", None)
        self.assertFalse(result)

    # Tests for extract_coordinate_data()
    def test_extract_coordinate_data_sca_package(self):
        parser = SnykIssueApiParser()
        coordinates = [
            {
                "reachability": "reachable",
                "representations": [
                    {
                        "dependency": {
                            "package_name": "pillow",
                            "package_version": "9.5.0",
                        },
                    },
                ],
            },
        ]
        file_path, line, component_name, component_version, reachable, impact_locations = parser.extract_coordinate_data(
            is_type_code=False, coordinates=coordinates,
        )

        self.assertEqual("pillow", file_path)
        self.assertIsNone(line)
        self.assertEqual("pillow", component_name)
        self.assertEqual("9.5.0", component_version)
        self.assertTrue(reachable)
        self.assertEqual([], impact_locations)

    def test_extract_coordinate_data_code_source_location(self):
        parser = SnykIssueApiParser()
        coordinates = [
            {
                "representations": [
                    {
                        "sourceLocation": {
                            "file": "path/to/file.py",
                            "commit_id": "abc123",
                            "region": {
                                "start": {"line": 10, "column": 5},
                                "end": {"line": 12, "column": 15},
                            },
                        },
                    },
                ],
            },
        ]
        file_path, line, component_name, component_version, reachable, impact_locations = parser.extract_coordinate_data(
            is_type_code=True, coordinates=coordinates,
        )

        self.assertEqual("path/to/file.py", file_path)
        self.assertEqual(10, line)
        self.assertIsNone(component_name)
        self.assertIsNone(component_version)
        self.assertFalse(reachable)
        self.assertEqual(1, len(impact_locations))
        self.assertIn("File: path/to/file.py", impact_locations[0])

    # Tests for get_exploit_details()
    def test_get_exploit_details_with_sources(self):
        parser = SnykIssueApiParser()
        exploit_details = {
            "sources": ["CISA", "PoC in GitHub", "Snyk"],
        }
        result = parser.get_exploit_details(exploit_details)
        expected = ["Exploit Sources: CISA, PoC in GitHub, Snyk", ""]
        self.assertEqual(expected, result)

    def test_get_exploit_details_empty_sources(self):
        parser = SnykIssueApiParser()
        exploit_details = {"sources": []}
        result = parser.get_exploit_details(exploit_details)
        self.assertIsNone(result)

    def test_get_exploit_details_none(self):
        parser = SnykIssueApiParser()
        result = parser.get_exploit_details(None)
        self.assertIsNone(result)

    # Tests for extract_problems()
    def test_extract_problems_with_data(self):
        parser = SnykIssueApiParser()
        problems = [
            {
                "id": "SNYK-PYTHON-PILLOW-6219984",
                "source": "SNYK",
                "type": "vulnerability",
                "updated_at": "2025-09-11T18:25:24.263774Z",
            },
        ]
        result = parser.extract_problems(problems)
        expected = [
            "id: SNYK-PYTHON-PILLOW-6219984",
            "Source: SNYK",
            "Type: vulnerability",
            "",  # empty line because there is no URL
            "Last Updated: 2025-09-11T18:25:24.263774Z",
            "",
        ]
        self.assertEqual(expected, result)

    def test_extract_problems_with_url(self):
        parser = SnykIssueApiParser()
        problems = [
            {
                "id": "CVE-2023-4863",
                "source": "NVD",
                "type": "vulnerability",
                "updated_at": "2025-09-19T09:01:27.147504Z",
                "url": "https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
            },
        ]
        result = parser.extract_problems(problems)
        expected = [
            "id: CVE-2023-4863",
            "Source: NVD",
            "Type: vulnerability",
            "URL: https://nvd.nist.gov/vuln/detail/CVE-2023-4863",
            "Last Updated: 2025-09-19T09:01:27.147504Z",
            "",
        ]
        self.assertEqual(expected, result)

    def test_extract_problems_empty(self):
        parser = SnykIssueApiParser()
        result = parser.extract_problems([])
        self.assertIsNone(result)

    # Tests for extract_problem_ids()
    def test_extract_problem_ids_with_data(self):
        parser = SnykIssueApiParser()
        problems = [
            {
                "id": "SNYK-PYTHON-PILLOW-6219984",
                "source": "SNYK",
                "type": "vulnerability",
            },
            {
                "id": "CVE-2023-1234",
                "source": "NVD",
                "type": "vulnerability",
            },
        ]
        result = parser.extract_problem_ids(problems)
        expected = ["SNYK-PYTHON-PILLOW-6219984", "CVE-2023-1234"]
        self.assertEqual(expected, result)

    def test_extract_problem_ids_empty(self):
        parser = SnykIssueApiParser()
        result = parser.extract_problem_ids([])
        self.assertEqual([], result)

    def test_extract_problem_ids_missing_id(self):
        parser = SnykIssueApiParser()
        problems = [
            {
                "source": "SNYK",
                "type": "vulnerability",
            },
        ]
        result = parser.extract_problem_ids(problems)
        self.assertEqual([], result)

    # Tests for extract_risk_score()
    def test_extract_risk_score_with_valid_data(self):
        parser = SnykIssueApiParser()
        risk = {
            "score": {
                "model": "v1",
                "value": 115,
            },
        }
        result = parser.extract_risk_score(risk)
        self.assertEqual("Risk Score: 115 (Model: v1)", result)

    def test_extract_risk_score_no_score(self):
        parser = SnykIssueApiParser()
        risk = {"factors": []}
        result = parser.extract_risk_score(risk)
        self.assertIsNone(result)

    def test_extract_risk_score_none(self):
        parser = SnykIssueApiParser()
        result = parser.extract_risk_score(None)
        self.assertIsNone(result)

    # Tests for extract_cvss_severities()
    def test_extract_cvss_severities_v3_and_v4(self):
        parser = SnykIssueApiParser()
        severities = [
            {
                "level": "critical",
                "modification_time": "2025-06-03T14:56:22.921Z",
                "score": 9.3,
                "source": "Snyk",
                "vector": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N",
                "version": "4.0",
            },
            {
                "level": "critical",
                "modification_time": "2025-06-03T14:56:22.921Z",
                "score": 9.1,
                "source": "Snyk",
                "vector": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
                "version": "3.1",
            },
        ]

        v3vector, v3score = parser.extract_cvss_severities(severities, "3")
        v4vector, v4score = parser.extract_cvss_severities(severities, "4")

        self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N", v3vector)
        self.assertEqual(9.1, v3score)
        self.assertEqual("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:N/SC:N/SI:N/SA:N", v4vector)
        self.assertEqual(9.3, v4score)

    def test_extract_cvss_severities_no_match(self):
        parser = SnykIssueApiParser()
        severities = [
            {
                "level": "high",
                "score": 7.5,
                "vector": "CVSS:2.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
                "version": "2.0",
            },
        ]

        v3vector, v3score = parser.extract_cvss_severities(severities, "3")
        v4vector, v4score = parser.extract_cvss_severities(severities, "4")

        self.assertIsNone(v3vector)
        self.assertIsNone(v3score)
        self.assertIsNone(v4vector)
        self.assertIsNone(v4score)

    # Tests for extract_convert_created_date()
    def test_extract_convert_created_date_valid(self):
        parser = SnykIssueApiParser()

        # Test valid ISO format
        in_date = "2025-09-11T18:25:22.457Z"
        date = parser.extract_convert_created_date(in_date)
        self.assertEqual("2025-09-11", date)

        # Test another valid format
        in_date2 = "2024-12-13T12:29:59.035Z"
        date2 = parser.extract_convert_created_date(in_date2)
        self.assertEqual("2024-12-13", date2)

    def test_extract_convert_created_date_invalid(self):
        parser = SnykIssueApiParser()

        # Test invalid date
        result = parser.extract_convert_created_date("invalid-date")
        self.assertIsNone(result)

        # Test None input
        result = parser.extract_convert_created_date(None)
        self.assertIsNone(result)
