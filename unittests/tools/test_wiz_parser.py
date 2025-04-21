import datetime

from dojo.models import Test
from dojo.tools.wiz.parser import WizParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestWizParser(DojoTestCase):
    def test_no_findings(self):
        with open(get_unit_tests_scans_path("wiz") / "no_findings.csv", encoding="utf-8") as testfile:
            parser = WizParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(0, len(findings))

    def test_one_findings(self):
        with open(get_unit_tests_scans_path("wiz") / "one_finding.csv", encoding="utf-8") as testfile:
            parser = WizParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(1, len(findings))
            finding = findings[0]
            self.assertEqual("AKS role/cluster role assigned permissions that contain wildcards ", finding.title)
            self.assertEqual("Informational", finding.severity)

    def test_multiple_findings(self):
        with open(get_unit_tests_scans_path("wiz") / "multiple_findings.csv", encoding="utf-8") as testfile:
            parser = WizParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(98, len(findings))
            finding = findings[0]
            self.assertEqual("AKS role/cluster role assigned permissions that contain wildcards ", finding.title)
            self.assertEqual("Informational", finding.severity)
            finding = findings[1]
            self.assertEqual("Unusual activity by a principal from previously unseen country", finding.title)
            self.assertEqual("High", finding.severity)

            finding = findings[7]
            self.assertEqual("AKS user/service accounts with the privileges to create pods", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(False, finding.is_mitigated)
            self.assertEqual(False, finding.out_of_scope)

            finding = findings[9]
            self.assertEqual("AKS cluster contains a pod running containers with added capabilities", finding.title)
            self.assertEqual(False, finding.active)
            self.assertEqual(True, finding.is_mitigated)
            self.assertEqual(False, finding.out_of_scope)

            finding = findings[11]
            self.assertEqual("Container using an image with high/critical severity network vulnerabilities with a known exploit", finding.title)
            self.assertEqual(False, finding.active)
            self.assertEqual(False, finding.is_mitigated)
            self.assertEqual(True, finding.out_of_scope)

            finding = findings[20]
            self.assertEqual(
                "User/service account with get/list/watch permissions on secrets in an AKS cluster", finding.title,
            )
            self.assertEqual("Informational", finding.severity)

    def test_sca_format(self):
        with open(get_unit_tests_scans_path("wiz") / "sca_format.csv", encoding="utf-8") as testfile:
            parser = WizParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

            finding = findings[0]
            self.assertEqual("github.com/containerd/containerd: CVE-2024-39474", finding.title)
            self.assertEqual("Low", finding.severity)
            self.assertEqual("github.com/containerd/containerd", finding.component_name)
            self.assertEqual("1.4.0", finding.component_version)
            self.assertIn("goog-k8s-cluster-location: us-central1", finding.unsaved_tags)
            self.assertIn("CVE-2024-39474", finding.unsaved_vulnerability_ids)
            self.assertIn("**Location Path**: `/home/kubernetes/bin/containerd-gcfs-grpc`", finding.description)
            self.assertIn("**Location Path**: `/home/kubernetes/bin/containerd-gcfs-grpc`", finding.mitigation)

            finding = findings[1]
            self.assertEqual("k8s.io/apimachinery: CVE-2024-36891", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("k8s.io/apimachinery", finding.component_name)
            self.assertEqual("0.17.2", finding.component_version)
            self.assertIn("goog-k8s-cluster-location: us-central1", finding.unsaved_tags)
            self.assertIn("CVE-2024-36891", finding.unsaved_vulnerability_ids)
            self.assertIn("**Location Path**: `/home/kubernetes/bin/log-counter`", finding.description)
            self.assertIn("**Location Path**: `/home/kubernetes/bin/log-counter`", finding.mitigation)

            finding = findings[2]
            self.assertEqual("kernel: GHSA-c9cp-9c75-9v8c", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("kernel", finding.component_name)
            self.assertEqual("109.17800.218.33", finding.component_version)
            self.assertIn("goog-k8s-cluster-location: us-central1", finding.unsaved_tags)
            self.assertIn("GHSA-c9cp-9c75-9v8c", finding.unsaved_vulnerability_ids)
            self.assertNotIn("**Location Path**:", finding.description)
            self.assertNotIn("**Location Path**:", finding.mitigation)

            finding = findings[3]
            self.assertEqual("kernel: CVE-2020-8559", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("kernel", finding.component_name)
            self.assertEqual("109.17800.218.33", finding.component_version)
            self.assertIn("goog-k8s-cluster-location: us-central1", finding.unsaved_tags)
            self.assertIn("CVE-2020-8559", finding.unsaved_vulnerability_ids)
            self.assertNotIn("**Location Path**:", finding.description)
            self.assertNotIn("**Location Path**:", finding.mitigation)

            finding = findings[4]
            self.assertEqual("kernel: CVE-2024-36891", finding.title)
            self.assertEqual("Medium", finding.severity)
            self.assertEqual("kernel", finding.component_name)
            self.assertEqual("109.17800.218.33", finding.component_version)
            self.assertIn("goog-k8s-cluster-location: us-central1", finding.unsaved_tags)
            self.assertIn("CVE-2024-36891", finding.unsaved_vulnerability_ids)
            self.assertNotIn("**Location Path**:", finding.description)
            self.assertNotIn("**Location Path**:", finding.mitigation)

    def test_resolved_findings(self):
        with open(get_unit_tests_scans_path("wiz") / "resolved_findings.csv", encoding="utf-8") as testfile:
            parser = WizParser()
            findings = parser.get_findings(testfile, Test())
            for finding in findings:
                for endpoint in finding.unsaved_endpoints:
                    endpoint.clean()
            self.assertEqual(3, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("AKS role/cluster role assigned permissions that contain wildcards ISO_DATE", finding.title)
                self.assertEqual(True, finding.is_mitigated)
                self.assertEqual(datetime.date(2023, 1, 25), finding.date.date())
                self.assertEqual(datetime.date(1999, 1, 25), finding.mitigated.date())
                self.assertEqual(datetime.date(2023, 1, 25), finding.date.date())
                self.assertEqual("0029ee49-c676-432f-8690-12f2862ec708", finding.unique_id_from_tool)

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("AKS cluster contains a pod running containers with added capabilities SPECIAL_DATE", finding.title)
                self.assertEqual(True, finding.is_mitigated)
                self.assertEqual(datetime.date(2024, 1, 24), finding.date.date())
                self.assertEqual(datetime.date(2025, 4, 3), finding.mitigated.date())
                self.assertEqual("02fd8a0d-16fa-4da0-aa49-a99694365d41", finding.unique_id_from_tool)
                self.maxDiff = None
                self.assertIn("Resolution: CONTROL_DISABLED", finding.mitigation)

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("AKS cluster contains a pod running containers with added capabilities UNKNOWN_DATE_FORMAT", finding.title)
                self.assertEqual(True, finding.is_mitigated)
                self.assertEqual(datetime.date(2024, 1, 24), finding.date.date())
                self.assertEqual(None, finding.mitigated)
                self.assertEqual("02fd8a0d-16fa-4da0-aa49-a99694365d41", finding.unique_id_from_tool)
                self.maxDiff = None
                self.assertIn("Resolution: ISSUE_FIXED", finding.mitigation)
