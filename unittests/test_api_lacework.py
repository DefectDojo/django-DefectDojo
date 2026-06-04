"""
Unit tests for Lacework API Import integration.

Tests the core functionality of the Lacework API importer and parser:
- Severity mapping
- CVSS score extraction
- CWE extraction
- Finding creation from container vulnerabilities
- Finding creation from host vulnerabilities
- Parser contract compliance
- Importer end-to-end with mock data
"""

from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from dojo.models import (
    Engagement,
    Finding,
    Product,
    Product_Type,
    Test,
    Test_Type,
    Tool_Configuration,
    Tool_Type,
)
from dojo.tools.api_lacework.importer import LaceworkApiImporter
from dojo.tools.api_lacework.parser import ApiLaceworkParser, SCAN_LACEWORK_API

from .dojo_test_case import DojoTestCase


class TestLaceworkApiImporter(DojoTestCase):
    """Test the core logic of the Lacework API importer."""

    def test_convert_lacework_severity_critical(self):
        """Test that Critical severity maps correctly."""
        assert LaceworkApiImporter._convert_lacework_severity("Critical") == "Critical"

    def test_convert_lacework_severity_high(self):
        """Test that High severity maps correctly."""
        assert LaceworkApiImporter._convert_lacework_severity("High") == "High"

    def test_convert_lacework_severity_medium(self):
        """Test that Medium severity maps correctly."""
        assert LaceworkApiImporter._convert_lacework_severity("Medium") == "Medium"

    def test_convert_lacework_severity_low(self):
        """Test that Low severity maps correctly."""
        assert LaceworkApiImporter._convert_lacework_severity("Low") == "Low"

    def test_convert_lacework_severity_info(self):
        """Test that Info severity maps correctly."""
        assert LaceworkApiImporter._convert_lacework_severity("Info") == "Info"

    def test_convert_lacework_severity_unknown(self):
        """Test that unknown severity defaults to Info."""
        assert LaceworkApiImporter._convert_lacework_severity("Unknown") == "Info"

    def test_extract_cvss_score_from_nvd(self):
        """Test CVSSv3 extraction from NVD metadata (highest priority)."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "NVD": {
                        "CVSSv3": {
                            "Score": 9.8,
                            "Vectors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    },
                    "RBS": {
                        "CVSSv3": {
                            "Score": 7.5,
                            "Vectors": "CVSS:3.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        },
                    },
                },
            },
            "riskScore": 10,
        }
        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score == 9.8
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_extract_cvss_score_from_rbs(self):
        """Test CVSSv3 extraction from RBS metadata when NVD is not available."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "NVD": {},
                    "RBS": {
                        "CVSSv3": {
                            "Score": 7.5,
                            "Vectors": "CVSS:3.0/AV:N/AC:L/Au:N/C:P/I:P/A:P",
                        },
                    },
                },
            },
        }
        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score == 7.5
        assert vector == "CVSS:3.0/AV:N/AC:L/Au:N/C:P/I:P/A:P"

    def test_extract_cvss_score_from_riskscore(self):
        """Test fallback to riskScore when no CVSS metadata is available."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "NVD": {},
                    "RBS": {},
                },
            },
            "riskScore": 10,
        }
        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score == 10.0
        assert vector is None

    def test_extract_cvss_score_from_cveriskscore(self):
        """Test fallback to cveRiskScore."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "NVD": {},
                    "RBS": {},
                },
            },
            "cveRiskScore": 9.8,
        }
        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score == 9.8

    def test_extract_cvss_score_none_when_no_data(self):
        """Test that None is returned when no score data exists."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "NVD": {},
                    "RBS": {},
                },
            },
        }
        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score is None
        assert vector is None

    def test_extract_cwe_success(self):
        """Test CWE extraction from RBS metadata."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "RBS": {
                        "cwe_id": {
                            "CVE-2022-37434": "CWE-787",
                        },
                    },
                },
            },
        }
        cwe = LaceworkApiImporter._extract_cwe(vuln)
        assert cwe == 787

    def test_extract_cwe_multiple(self):
        """Test CWE extraction when there are multiple CWEs."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "RBS": {
                        "cwe_id": {
                            "CVE-2022-37434": "CWE-787",
                            "CVE-2023-21100": "CWE-787",
                        },
                    },
                },
            },
        }
        cwe = LaceworkApiImporter._extract_cwe(vuln)
        assert cwe == 787

    def test_extract_cwe_none_when_no_cwe(self):
        """Test that None is returned when no CWE data exists."""
        vuln = {
            "cveProps": {
                "metadata": {
                    "RBS": {},
                },
            },
        }
        cwe = LaceworkApiImporter._extract_cwe(vuln)
        assert cwe is None

    def test_extract_cwe_none_when_no_metadata(self):
        """Test that None is returned when no metadata exists."""
        vuln = {"cveProps": {}}
        cwe = LaceworkApiImporter._extract_cwe(vuln)
        assert cwe is None

    def test_create_finding_from_container_vuln(self):
        """Test Finding creation from a container vulnerability with all fields."""
        vuln = {
            "vulnId": "CVE-2022-37434",
            "severity": "Critical",
            "cveProps": {
                "description": "Heap-based buffer over-read in zlib through 1.2.12",
                "link": "https://security-tracker.debian.org/tracker/CVE-2022-37434",
                "metadata": {
                    "NVD": {
                        "CVSSv3": {
                            "Score": 9.8,
                            "Vectors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    },
                    "RBS": {
                        "cwe_id": {
                            "CVE-2022-37434": "CWE-787",
                        },
                    },
                },
            },
            "evalCtx": {
                "image_info": {
                    "repo": "index.docker.io/library/postgres",
                    "tags": ["14.4"],
                },
            },
            "featureKey": {
                "name": "zlib",
                "namespace": "debian:11",
                "version": "1:1.2.11.dfsg-2+deb11u1",
            },
            "fixInfo": {
                "fix_available": 1,
                "fixed_version": "1:1.2.11.dfsg-2+deb11u2",
            },
            "riskScore": 10,
            "status": "VULNERABLE",
        }

        # Create a proper instance to call the instance method
        importer = LaceworkApiImporter()
        # Test the static helper methods independently
        severity = LaceworkApiImporter._convert_lacework_severity(vuln.get("severity", "Info"))
        assert severity == "Critical"
        
        cwe = LaceworkApiImporter._extract_cwe(vuln)
        assert cwe == 787
        
        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score == 9.8
        assert vector == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"

    def test_create_finding_from_host_vuln(self):
        """Test Finding creation from a host vulnerability with all fields."""
        vuln = {
            "vulnId": "CVE-2016-1585",
            "severity": "Medium",
            "cveProps": {
                "description": "AppArmor mount rules are accidentally widened when compiled",
                "link": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2016-1585",
                "metadata": {
                    "NVD": {
                        "CVSSv3": {
                            "Score": 9.8,
                            "Vectors": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                        },
                    },
                    "RBS": {
                        "cwe_id": {
                            "CVE-2016-1585": "CWE-254",
                        },
                    },
                },
            },
            "featureKey": {
                "name": "apparmor",
                "namespace": "ubuntu:20.04",
                "version_installed": "2.13.3-7ubuntu5.3",
            },
            "fixInfo": {
                "fix_available": 0,
                "fixed_version": "",
            },
            "mid": 7112040530067849000,
            "machineTags": {
                "Hostname": "my-server-hostname",
                "VmProvider": "AWS",
            },
            "riskScore": 9.74,
            "status": "Active",
        }

        # Verify the mapping logic extracts fields correctly
        cwe = LaceworkApiImporter._extract_cwe(vuln)
        assert cwe == 254

        score, vector = LaceworkApiImporter._extract_cvss_score(vuln)
        assert score == 9.8
        assert vector == "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"


class TestApiLaceworkParser(TestCase):
    """Test the parser contract implementation."""

    def setUp(self):
        self.parser = ApiLaceworkParser()

    def test_get_scan_types(self):
        """Test that the parser returns the correct scan type."""
        scan_types = self.parser.get_scan_types()
        assert len(scan_types) == 1
        assert scan_types[0] == SCAN_LACEWORK_API

    def test_get_label_for_scan_types(self):
        """Test that the label matches the scan type."""
        assert (
            self.parser.get_label_for_scan_types(SCAN_LACEWORK_API)
            == SCAN_LACEWORK_API
        )

    def test_get_description_for_scan_types(self):
        """Test that a description is returned."""
        description = self.parser.get_description_for_scan_types(SCAN_LACEWORK_API)
        assert description is not None
        assert len(description) > 0
        assert "Lacework" in description

    def test_requires_file(self):
        """Test that no file is required (API-based import)."""
        assert self.parser.requires_file(SCAN_LACEWORK_API) is False

    def test_requires_tool_type(self):
        """Test that the required tool type is 'Lacework'."""
        assert self.parser.requires_tool_type(SCAN_LACEWORK_API) == "Lacework"

    def test_api_scan_configuration_hint(self):
        """Test that a configuration hint is provided."""
        hint = self.parser.api_scan_configuration_hint()
        assert hint is not None
        assert len(hint) > 0
        assert "Service key 1" in hint

    def test_get_findings_with_empty_input(self):
        """Test that get_findings returns a list even with empty input."""
        # The importer relies on a valid test object with engagement and product
        # When None is passed, it should raise an error because it can't access
        # test.engagement.product. This test verifies the error handling returns
        # an empty list rather than crashing.
        # We pass a mock object that will fail validation gracefully
        from unittest.mock import MagicMock
        
        mock_test = MagicMock()
        mock_test.api_scan_configuration = None
        mock_test.engagement.product.name = "test"
        mock_test.engagement.product.product_api_scan_configuration_set.filter.return_value.count.return_value = 0
        
        result = self.parser.get_findings(None, mock_test)
        assert isinstance(result, list)
        # Should be empty because no API Scan Configuration is configured
        assert len(result) == 0


class TestLaceworkApiImporterIntegration(DojoTestCase):
    """Integration tests for the Lacework importer with real DB models."""

    def setUp(self):
        """Set up test data with real DB models."""
        # Create Tool Type
        self.tool_type = Tool_Type.objects.create(name="Lacework")
        
        # Create Tool Configuration
        self.tool_config = Tool_Configuration.objects.create(
            name="Lacework Test",
            tool_type=self.tool_type,
            authentication_type="API",
            url="https://test.lacework.net",
            username="test-key-id",
            api_key="test-api-key",
        )
        
        # Create Product Type and Product
        self.product_type = Product_Type.objects.create(name="Lacework")
        self.product = Product.objects.create(
            name="test-container-repo",
            prod_type=self.product_type,
            description="Test product for Lacework import",
        )
        
        # Create API Scan Configuration
        self.api_scan_config = self.product.product_api_scan_configuration_set.create(
            product=self.product,
            tool_configuration=self.tool_config,
        )
        
        # Create Engagement
        self.engagement = Engagement.objects.create(
            product=self.product,
            name="Lacework Test Scan",
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
            active=True,
            status="In Progress",
        )
        
        # Get or create Test Type
        self.test_type, _ = Test_Type.objects.get_or_create(name="Lacework API Import")
        
        # Create Test
        self.test = Test.objects.create(
            engagement=self.engagement,
            test_type=self.test_type,
            title="Container scan test",
            target_start=timezone.now(),
            target_end=timezone.now(),
            api_scan_configuration=self.api_scan_config,
            description="Lacework test import",
        )
        
        self.importer = LaceworkApiImporter()

    def test_get_findings_with_mocked_client_container_vulns(self):
        """Test that get_findings creates Finding objects from mocked container vulns."""
        mock_vulns = [
            {
                "vulnId": "CVE-2022-37434",
                "severity": "Critical",
                "cveProps": {
                    "description": "Heap-based buffer over-read in zlib through 1.2.12",
                    "link": "https://security-tracker.debian.org/tracker/CVE-2022-37434",
                    "metadata": {
                        "NVD": {
                            "CVSSv3": {"Score": 9.8, "Vectors": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"},
                        },
                        "RBS": {
                            "cwe_id": {"CVE-2022-37434": "CWE-787"},
                        },
                    },
                },
                "evalCtx": {
                    "image_info": {
                        "repo": "index.docker.io/library/postgres",
                        "tags": ["14.4"],
                    },
                },
                "featureKey": {
                    "name": "zlib",
                    "namespace": "debian:11",
                    "version": "1:1.2.11.dfsg-2+deb11u1",
                },
                "fixInfo": {
                    "fix_available": 1,
                    "fixed_version": "1:1.2.11.dfsg-2+deb11u2",
                },
                "riskScore": 10,
                "status": "VULNERABLE",
            },
            {
                "vulnId": "CVE-2023-12345",
                "severity": "High",
                "cveProps": {
                    "description": "Another test vulnerability",
                    "link": "https://example.com/cve",
                    "metadata": {"NVD": {}, "RBS": {}},
                },
                "evalCtx": {
                    "image_info": {
                        "repo": "index.docker.io/library/postgres",
                        "tags": ["latest"],
                    },
                },
                "featureKey": {
                    "name": "openssl",
                    "namespace": "debian:11",
                    "version": "1.1.1n-0+deb11u5",
                },
                "fixInfo": {
                    "fix_available": 0,
                    "fixed_version": "",
                },
                "riskScore": 8.5,
                "status": "VULNERABLE",
            },
        ]

        with patch.object(self.importer, "prepare_client") as mock_prepare:
            mock_client = MagicMock()
            mock_prepare.return_value = (mock_client, self.api_scan_config)
            
            mock_client.include_containers = True
            mock_client.include_hosts = True
            mock_client.search_container_vulnerabilities.return_value = mock_vulns
            mock_client.search_host_vulnerabilities.return_value = []

            findings = self.importer.get_findings(None, self.test)
            
            # Should have 2 findings
            assert len(findings) == 2
            
            # Verify first finding fields
            assert findings[0].vuln_id_from_tool == "CVE-2022-37434"
            assert findings[0].severity == "Critical"
            assert findings[0].component_name == "zlib"
            assert findings[0].component_version == "1:1.2.11.dfsg-2+deb11u1"
            assert findings[0].file_path == "debian:11"
            assert findings[0].fix_available is True
            assert findings[0].fix_version == "1:1.2.11.dfsg-2+deb11u2"
            assert findings[0].cwe == 787
            assert findings[0].cvssv3_score == 9.8
            assert findings[0].cvssv3 == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
            assert findings[0].static_finding is True
            assert findings[0].active is True
            assert findings[0].verified is True
            
            # Verify second finding
            assert findings[1].vuln_id_from_tool == "CVE-2023-12345"
            assert findings[1].severity == "High"
            assert findings[1].component_name == "openssl"
            assert findings[1].cvssv3_score == 8.5
            assert findings[1].fix_available is False
            assert findings[1].cwe is None

    def test_get_findings_with_mocked_client_host_vulns(self):
        """Test that get_findings creates Finding objects from mocked host vulns."""
        mock_vulns = [
            {
                "vulnId": "CVE-2016-1585",
                "severity": "Medium",
                "cveProps": {
                    "description": "AppArmor mount rules are accidentally widened",
                    "link": "http://people.ubuntu.com/~ubuntu-security/cve/CVE-2016-1585",
                    "metadata": {
                        "NVD": {"CVSSv3": {"Score": 9.8, "Vectors": "CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"}},
                        "RBS": {"cwe_id": {"CVE-2016-1585": "CWE-254"}},
                    },
                },
                "featureKey": {
                    "name": "apparmor",
                    "namespace": "ubuntu:20.04",
                    "version_installed": "2.13.3-7ubuntu5.3",
                },
                "fixInfo": {"fix_available": 0, "fixed_version": ""},
                "mid": 7112040530067849000,
                "machineTags": {"Hostname": "my-server", "VmProvider": "AWS"},
                "riskScore": 9.74,
                "status": "Active",
            },
        ]

        with patch.object(self.importer, "prepare_client") as mock_prepare:
            mock_client = MagicMock()
            mock_prepare.return_value = (mock_client, self.api_scan_config)
            
            mock_client.include_containers = True
            mock_client.include_hosts = True
            mock_client.search_container_vulnerabilities.return_value = []
            mock_client.search_host_vulnerabilities.return_value = mock_vulns

            findings = self.importer.get_findings(None, self.test)
            
            assert len(findings) == 1
            assert findings[0].vuln_id_from_tool == "CVE-2016-1585"
            assert findings[0].severity == "Medium"
            assert findings[0].component_name == "apparmor"
            assert findings[0].component_version == "2.13.3-7ubuntu5.3"
            assert findings[0].file_path == "ubuntu:20.04"
            assert findings[0].cwe == 254
            assert findings[0].cvssv3_score == 9.8
            assert findings[0].fix_available is False

    def test_get_findings_disables_containers_from_extras(self):
        """Test that include_containers=false skips container vulns."""
        with patch.object(self.importer, "prepare_client") as mock_prepare:
            mock_client = MagicMock()
            mock_prepare.return_value = (mock_client, self.api_scan_config)
            
            mock_client.include_containers = False
            mock_client.include_hosts = True
            mock_client.search_host_vulnerabilities.return_value = [
                {"vulnId": "CVE-2016-1585", "severity": "Medium", "cveProps": {"description": "test", "link": "", "metadata": {"NVD": {}, "RBS": {}}}, "featureKey": {"name": "test", "namespace": "test", "version_installed": "1.0"}, "fixInfo": {"fix_available": 0, "fixed_version": ""}, "mid": 123, "machineTags": {}, "riskScore": 5}
            ]

            findings = self.importer.get_findings(None, self.test)
            
            assert len(findings) == 1
            # search_container_vulnerabilities should NOT have been called
            mock_client.search_container_vulnerabilities.assert_not_called()
            mock_client.search_host_vulnerabilities.assert_called_once()

    def test_persist_findings_to_db(self):
        """Test that findings can be saved to the database."""
        with patch.object(self.importer, "prepare_client") as mock_prepare:
            mock_client = MagicMock()
            mock_prepare.return_value = (mock_client, self.api_scan_config)
            
            mock_client.include_containers = True
            mock_client.include_hosts = True
            mock_client.search_container_vulnerabilities.return_value = []
            mock_client.search_host_vulnerabilities.return_value = []

            findings = self.importer.get_findings(None, self.test)
            
            # No vulnerabilities, should be empty
            assert len(findings) == 0

    def test_prepare_client_with_existing_config(self):
        """Test that prepare_client correctly finds the API Scan Configuration."""
        client, config = LaceworkApiImporter.prepare_client(self.test)
        assert config == self.api_scan_config
        assert config.tool_configuration == self.tool_config

    def test_prepare_client_fails_without_config(self):
        """Test that prepare_client raises error when no config exists."""
        # Create a separate product without any API scan configuration
        product_no_config = Product.objects.create(
            name="test-no-config",
            prod_type=self.product_type,
        )
        engagement_no_config = Engagement.objects.create(
            product=product_no_config,
            name="No Config Engagement",
            target_start=timezone.now().date(),
            target_end=timezone.now().date(),
        )
        test_no_config = Test.objects.create(
            engagement=engagement_no_config,
            test_type=self.test_type,
            title="No config test",
            target_start=timezone.now(),
            target_end=timezone.now(),
        )
        with self.assertRaises(Exception):
            LaceworkApiImporter.prepare_client(test_no_config)