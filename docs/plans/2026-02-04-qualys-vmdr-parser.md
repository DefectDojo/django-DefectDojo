# Qualys VMDR Parser Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Create a DefectDojo parser for Qualys VMDR CSV exports (QID and CVE formats).

**Architecture:** Multi-format dispatcher pattern with shared helpers module. Main parser.py detects format and delegates to qid_parser.py or cve_parser.py. All shared utilities in helpers.py to avoid circular imports.

**Tech Stack:** Python 3.12, Django, csv module, dateutil.parser

---

## Task 1: Create Package Structure

**Files:**
- Create: `dojo/tools/qualys_vmdr/__init__.py`

**Step 1: Create empty __init__.py**

```python
```

(Empty file - required for Python package)

**Step 2: Verify directory structure**

Run: `ls -la dojo/tools/qualys_vmdr/`
Expected: Shows `__init__.py` file

**Step 3: Commit**

```bash
git add dojo/tools/qualys_vmdr/__init__.py
git commit -m "feat(parser): add qualys_vmdr package structure

Authored by T. Walker - DefectDojo"
```

---

## Task 2: Create Test Scan Files - QID Format

**Files:**
- Create: `unittests/scans/qualys_vmdr/no_vuln_qid.csv`
- Create: `unittests/scans/qualys_vmdr/one_vuln_qid.csv`
- Create: `unittests/scans/qualys_vmdr/many_vulns_qid.csv`

**Step 1: Create no_vuln_qid.csv (empty scan)**

```csv
"Asset Vuln Datalist Report,""04 Feb 2026 10:00AM GMT-0500"",""1"""
"TestCompany,""123 Test Street"",""Test City"",""None"",""12345"",""USA"""
"Test User,""testuser"",""IDM - Scanner VMDR"""
"QID,""Title"",""Severity"",""KB Severity"",""Type Detected"",""Last Detected"",""First Detected"",""Protocol"",""Port"",""Status"",""Asset Id"",""Asset Name"",""Asset IPV4"",""Asset IPV6"",""Solution"",""Asset Tags"",""Disabled"",""Ignored"",""QDS"",""QDS Severity"",""Detection AGE"",""Published Date"",""Patch Released"",""Category"",""RTI"",""Operating System"",""Last Fixed"",""Last Reopened"",""Times Detected"",""Threat"",""Vuln Patchable"",""Asset Critical Score"",""TruRisk Score"",""Vulnerability Tags"",""Results"",""Deep Scan Result"",""Detection Source"",""MITRE ATT&CK TACTIC ID"",""MITRE ATT&CK TACTIC NAME"",""MITRE ATT&CK TECHNIQUE ID"",""MITRE ATT&CK TECHNIQUE NAME"""
```

**Step 2: Create one_vuln_qid.csv (single finding)**

```csv
"Asset Vuln Datalist Report,""04 Feb 2026 10:00AM GMT-0500"",""1"""
"TestCompany,""123 Test Street"",""Test City"",""None"",""12345"",""USA"""
"Test User,""testuser"",""IDM - Scanner VMDR"""
"QID,""Title"",""Severity"",""KB Severity"",""Type Detected"",""Last Detected"",""First Detected"",""Protocol"",""Port"",""Status"",""Asset Id"",""Asset Name"",""Asset IPV4"",""Asset IPV6"",""Solution"",""Asset Tags"",""Disabled"",""Ignored"",""QDS"",""QDS Severity"",""Detection AGE"",""Published Date"",""Patch Released"",""Category"",""RTI"",""Operating System"",""Last Fixed"",""Last Reopened"",""Times Detected"",""Threat"",""Vuln Patchable"",""Asset Critical Score"",""TruRisk Score"",""Vulnerability Tags"",""Results"",""Deep Scan Result"",""Detection Source"",""MITRE ATT&CK TACTIC ID"",""MITRE ATT&CK TACTIC NAME"",""MITRE ATT&CK TECHNIQUE ID"",""MITRE ATT&CK TECHNIQUE NAME"""
"100269,""Microsoft Internet Explorer Security Update"",""5"",""5"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Apr 13, 2021 03:14 PM"",""'-"",""0"",""ACTIVE"",""119586089"",""TESTSERVER01"",""10.0.0.1"","""",""Apply the security update from Microsoft."",""Server,Production"",""No"",""No"",""72"",""HIGH"",""1756"",""Dec 08, 2015 04:36 PM"",""Dec 07, 2015 09:00 PM"",""Internet Explorer"",""Remote Code Execution"",""Windows Server 2019"","""","""",""100"",""Remote code execution vulnerability."",""Yes"",""1"",""174"","""",""Version detected: 11.0.100"",""'-"",""QUALYS"","""","""","""","""""
```

**Step 3: Create many_vulns_qid.csv (5 findings with varied severities)**

```csv
"Asset Vuln Datalist Report,""04 Feb 2026 10:00AM GMT-0500"",""1"""
"TestCompany,""123 Test Street"",""Test City"",""None"",""12345"",""USA"""
"Test User,""testuser"",""IDM - Scanner VMDR"""
"QID,""Title"",""Severity"",""KB Severity"",""Type Detected"",""Last Detected"",""First Detected"",""Protocol"",""Port"",""Status"",""Asset Id"",""Asset Name"",""Asset IPV4"",""Asset IPV6"",""Solution"",""Asset Tags"",""Disabled"",""Ignored"",""QDS"",""QDS Severity"",""Detection AGE"",""Published Date"",""Patch Released"",""Category"",""RTI"",""Operating System"",""Last Fixed"",""Last Reopened"",""Times Detected"",""Threat"",""Vuln Patchable"",""Asset Critical Score"",""TruRisk Score"",""Vulnerability Tags"",""Results"",""Deep Scan Result"",""Detection Source"",""MITRE ATT&CK TACTIC ID"",""MITRE ATT&CK TACTIC NAME"",""MITRE ATT&CK TECHNIQUE ID"",""MITRE ATT&CK TECHNIQUE NAME"""
"100001,""Information Disclosure Vulnerability"",""1"",""1"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Jan 01, 2026 10:00 AM"",""TCP"",""80"",""ACTIVE"",""100000001"",""WEBSERVER01"",""10.0.0.10"","""",""Review information disclosure."",""Web,Production"",""No"",""No"",""10"",""LOW"",""34"",""Jan 01, 2025 12:00 PM"","""",""Web Server"",""Information Disclosure"",""Ubuntu 22.04"","""","""",""5"",""May disclose server information."",""No"",""1"",""10"","""",""Server header exposed"",""'-"",""QUALYS"","""","""","""","""""
"100002,""SSL Certificate Expiring Soon"",""2"",""2"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Jan 15, 2026 10:00 AM"",""TCP"",""443"",""ACTIVE"",""100000002"",""WEBSERVER02"",""10.0.0.11"","""",""Renew SSL certificate."",""Web,Production"",""No"",""No"",""25"",""LOW"",""20"",""Jan 15, 2025 12:00 PM"","""",""SSL/TLS"",""Configuration Issue"",""Ubuntu 22.04"","""","""",""10"",""Certificate expires in 30 days."",""No"",""1"",""25"","""",""Cert expires: 2026-03-05"",""'-"",""QUALYS"","""","""","""","""""
"100003,""Outdated Software Version"",""3"",""3"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Dec 01, 2025 10:00 AM"",""TCP"",""22"",""FIXED"",""100000003"",""APPSERVER01"",""10.0.0.20,10.0.0.21"","""",""Update to latest version."",""App,Development"",""No"",""No"",""50"",""MEDIUM"",""65"",""Nov 01, 2025 12:00 PM"",""Nov 15, 2025 12:00 PM"",""Operating System"",""Known Vulnerabilities"",""CentOS 8"",""Jan 20, 2026 08:00 AM"","""",""15"",""Running outdated software version."",""Yes"",""2"",""50"","""",""OpenSSH 7.9 detected"",""'-"",""QUALYS"","""","""","""","""""
"100004,""Missing Security Patches"",""4"",""4"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Nov 15, 2025 10:00 AM"",""TCP"",""3389"",""ACTIVE"",""100000004"",""WINSERVER01"",""10.0.0.30"","""",""Apply security patches."",""Windows,Production"",""No"",""No"",""75"",""HIGH"",""82"",""Oct 01, 2025 12:00 PM"",""Oct 15, 2025 12:00 PM"",""Windows"",""Remote Code Execution,Privilege Escalation"",""Windows Server 2019"","""","""",""25"",""Missing critical security patches."",""Yes"",""3"",""100"","""",""KB5001234 missing"",""'-"",""QUALYS"","""","""","""","""""
"100005,""Critical RCE Vulnerability"",""5"",""5"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Oct 01, 2025 10:00 AM"",""TCP"",""445"",""ACTIVE"",""100000005"",""DBSERVER01"","""",""2001:db8::1"",""Apply vendor patch immediately."",""Database,Production,Critical"",""No"",""No"",""95"",""CRITICAL"",""127"",""Sep 01, 2025 12:00 PM"",""Sep 15, 2025 12:00 PM"",""Database"",""Remote Code Execution,Active Exploit"",""Windows Server 2016"","""","""",""50"",""Critical remote code execution."",""Yes"",""5"",""200"","""",""SMB vulnerability confirmed"",""'-"",""QUALYS"","""","""","""","""""
```

**Step 4: Verify files created**

Run: `ls -la unittests/scans/qualys_vmdr/`
Expected: Shows 3 QID CSV files

**Step 5: Commit**

```bash
git add unittests/scans/qualys_vmdr/
git commit -m "test(parser): add QID format test files for qualys_vmdr

Authored by T. Walker - DefectDojo"
```

---

## Task 3: Create Test Scan Files - CVE Format

**Files:**
- Create: `unittests/scans/qualys_vmdr/no_vuln_cve.csv`
- Create: `unittests/scans/qualys_vmdr/one_vuln_cve.csv`
- Create: `unittests/scans/qualys_vmdr/many_vulns_cve.csv`

**Step 1: Create no_vuln_cve.csv (empty scan)**

```csv
"Asset Vuln Datalist Report,""04 Feb 2026 10:00AM GMT-0500"",""1"""
"TestCompany,""123 Test Street"",""Test City"",""None"",""12345"",""USA"""
"Test User,""testuser"",""IDM - Scanner VMDR"""
"CVE,""CVE-Description"",""CVSSv2 Base (nvd)"",""CVSSv3.1 Base (nvd)"",""QID"",""Title"",""Severity"",""KB Severity"",""Type Detected"",""Last Detected"",""First Detected"",""Protocol"",""Port"",""Status"",""Asset Id"",""Asset Name"",""Asset IPV4"",""Asset IPV6"",""Solution"",""Asset Tags"",""Disabled"",""Ignored"",""QVS Score"",""Detection AGE"",""Published Date"",""Patch Released"",""Category"",""CVSS Rating Labels"",""RTI"",""Operating System"",""Last Fixed"",""Last Reopened"",""Times Detected"",""Threat"",""Vuln Patchable"",""Asset Critical Score"",""TruRisk Score"",""Vulnerability Tags"",""Results"",""Deep Scan Result"",""Detection Source"""
```

**Step 2: Create one_vuln_cve.csv (single finding)**

```csv
"Asset Vuln Datalist Report,""04 Feb 2026 10:00AM GMT-0500"",""1"""
"TestCompany,""123 Test Street"",""Test City"",""None"",""12345"",""USA"""
"Test User,""testuser"",""IDM - Scanner VMDR"""
"CVE,""CVE-Description"",""CVSSv2 Base (nvd)"",""CVSSv3.1 Base (nvd)"",""QID"",""Title"",""Severity"",""KB Severity"",""Type Detected"",""Last Detected"",""First Detected"",""Protocol"",""Port"",""Status"",""Asset Id"",""Asset Name"",""Asset IPV4"",""Asset IPV6"",""Solution"",""Asset Tags"",""Disabled"",""Ignored"",""QVS Score"",""Detection AGE"",""Published Date"",""Patch Released"",""Category"",""CVSS Rating Labels"",""RTI"",""Operating System"",""Last Fixed"",""Last Reopened"",""Times Detected"",""Threat"",""Vuln Patchable"",""Asset Critical Score"",""TruRisk Score"",""Vulnerability Tags"",""Results"",""Deep Scan Result"",""Detection Source"""
"CVE-2021-44228,""Apache Log4j2 remote code execution vulnerability"",""9.3"",""10.0"",""730143"",""Apache Log4j Remote Code Execution (Log4Shell)"",""5"",""5"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Dec 15, 2021 10:00 AM"",""TCP"",""8080"",""ACTIVE"",""200000001"",""JAVAAPP01"",""10.1.0.50"","""",""Upgrade Log4j to version 2.17.0 or later."",""Java,Production,Critical"",""No"",""No"",""100"",""1512"",""Dec 10, 2021 12:00 PM"",""Dec 17, 2021 12:00 PM"",""Java"",""CRITICAL"",""Remote Code Execution,Active Exploit,Zero Day"",""Ubuntu 20.04"","""","""",""500"",""Critical RCE via JNDI injection."",""Yes"",""5"",""500"","""",""Log4j 2.14.1 detected"",""'-"",""QUALYS"""
```

**Step 3: Create many_vulns_cve.csv (5 findings with varied CVEs)**

```csv
"Asset Vuln Datalist Report,""04 Feb 2026 10:00AM GMT-0500"",""1"""
"TestCompany,""123 Test Street"",""Test City"",""None"",""12345"",""USA"""
"Test User,""testuser"",""IDM - Scanner VMDR"""
"CVE,""CVE-Description"",""CVSSv2 Base (nvd)"",""CVSSv3.1 Base (nvd)"",""QID"",""Title"",""Severity"",""KB Severity"",""Type Detected"",""Last Detected"",""First Detected"",""Protocol"",""Port"",""Status"",""Asset Id"",""Asset Name"",""Asset IPV4"",""Asset IPV6"",""Solution"",""Asset Tags"",""Disabled"",""Ignored"",""QVS Score"",""Detection AGE"",""Published Date"",""Patch Released"",""Category"",""CVSS Rating Labels"",""RTI"",""Operating System"",""Last Fixed"",""Last Reopened"",""Times Detected"",""Threat"",""Vuln Patchable"",""Asset Critical Score"",""TruRisk Score"",""Vulnerability Tags"",""Results"",""Deep Scan Result"",""Detection Source"""
"CVE-2023-0001,""Information disclosure in component X"",""2.1"",""3.1"",""800001"",""Component X Information Disclosure"",""1"",""1"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Jan 10, 2026 10:00 AM"",""TCP"",""80"",""ACTIVE"",""300000001"",""SERVER01"",""192.168.1.10"","""",""Update component X."",""Web"",""No"",""No"",""15"",""25"",""Dec 01, 2022 12:00 PM"","""",""Web Application"",""LOW"",""Information Disclosure"",""Debian 11"","""","""",""3"",""Minor information disclosure."",""No"",""1"",""15"","""",""Header leak detected"",""'-"",""QUALYS"""
"CVE-2023-0002,""Denial of service vulnerability"",""5.0"",""5.3"",""800002"",""DoS Vulnerability in Service Y"",""2"",""2"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Jan 15, 2026 10:00 AM"",""TCP"",""443"",""ACTIVE"",""300000002"",""SERVER02"",""192.168.1.11"","""",""Apply vendor patch."",""Web,Production"",""No"",""No"",""30"",""20"",""Jan 01, 2023 12:00 PM"",""Jan 15, 2023 12:00 PM"",""Web Server"",""LOW"",""Denial of Service"",""Ubuntu 22.04"","""","""",""5"",""Can cause service disruption."",""Yes"",""2"",""30"","""",""Vulnerable endpoint found"",""'-"",""QUALYS"""
"CVE-2023-0003,""SQL injection vulnerability"",""7.5"",""6.5"",""800003"",""SQL Injection in Application Z"",""3"",""3"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Dec 20, 2025 10:00 AM"",""TCP"",""3306"",""FIXED"",""300000003"",""DBSERVER01"",""192.168.1.20"","""",""Sanitize user input."",""Database"",""No"",""No"",""60"",""46"",""Nov 15, 2022 12:00 PM"",""Dec 01, 2022 12:00 PM"",""Database"",""MEDIUM"",""SQL Injection"",""CentOS 8"",""Jan 25, 2026 08:00 AM"","""",""10"",""SQL injection allows data extraction."",""Yes"",""3"",""75"","""",""Error-based SQLi confirmed"",""'-"",""QUALYS"""
"CVE-2023-0004,""Privilege escalation vulnerability"",""7.2"",""7.8"",""800004"",""Local Privilege Escalation"",""4"",""4"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Nov 01, 2025 10:00 AM"",""'-"",""0"",""ACTIVE"",""300000004"",""WORKSTATION01"",""192.168.1.100,192.168.1.101"","""",""Apply security update."",""Workstation,Development"",""No"",""No"",""80"",""96"",""Oct 01, 2022 12:00 PM"",""Oct 20, 2022 12:00 PM"",""Operating System"",""HIGH"",""Privilege Escalation"",""Windows 10"","""","""",""20"",""Local user can gain admin privileges."",""Yes"",""3"",""120"","""",""Vulnerable driver detected"",""'-"",""QUALYS"""
"CVE-2023-0005,""Remote code execution vulnerability"",""10.0"",""9.8"",""800005"",""Critical RCE in Framework W"",""5"",""5"",""Confirmed"",""Feb 03, 2026 07:00 AM"",""Oct 15, 2025 10:00 AM"",""TCP"",""8443"",""ACTIVE"",""300000005"",""APPSERVER01"","""",""2001:db8::100"",""Upgrade framework immediately."",""App,Production,Critical"",""No"",""No"",""98"",""112"",""Sep 15, 2022 12:00 PM"",""Sep 30, 2022 12:00 PM"",""Application Framework"",""CRITICAL"",""Remote Code Execution,Active Exploit"",""Ubuntu 20.04"","""","""",""50"",""Unauthenticated RCE via deserialization."",""Yes"",""5"",""250"","""",""Exploit payload successful"",""'-"",""QUALYS"""
```

**Step 4: Verify files created**

Run: `ls -la unittests/scans/qualys_vmdr/`
Expected: Shows 6 CSV files total (3 QID + 3 CVE)

**Step 5: Commit**

```bash
git add unittests/scans/qualys_vmdr/
git commit -m "test(parser): add CVE format test files for qualys_vmdr

Authored by T. Walker - DefectDojo"
```

---

## Task 4: Write Failing Tests - Basic Structure

**Files:**
- Create: `unittests/tools/test_qualys_vmdr_parser.py`

**Step 1: Write initial test file with format detection and empty file tests**

```python
"""Unit tests for the Qualys VMDR parser."""

from dojo.models import Test
from dojo.tools.qualys_vmdr.parser import QualysVMDRParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestQualysVMDRParser(DojoTestCase):

    """Test cases for QualysVMDRParser."""

    def test_get_scan_types(self):
        """Test that parser returns correct scan type."""
        parser = QualysVMDRParser()
        self.assertEqual(["Qualys VMDR"], parser.get_scan_types())

    def test_get_label_for_scan_types(self):
        """Test that parser returns correct label."""
        parser = QualysVMDRParser()
        self.assertEqual("Qualys VMDR", parser.get_label_for_scan_types("Qualys VMDR"))

    def test_get_description_for_scan_types(self):
        """Test that parser returns a description."""
        parser = QualysVMDRParser()
        description = parser.get_description_for_scan_types("Qualys VMDR")
        self.assertIn("Qualys VMDR", description)

    def test_parse_qid_no_findings(self):
        """Test parsing QID format with no vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_cve_no_findings(self):
        """Test parsing CVE format with no vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "no_vuln_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(0, len(findings))

    def test_parse_qid_one_finding(self):
        """Test parsing QID format with single vulnerability."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_cve_one_finding(self):
        """Test parsing CVE format with single vulnerability."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(1, len(findings))

    def test_parse_qid_many_findings(self):
        """Test parsing QID format with multiple vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))

    def test_parse_cve_many_findings(self):
        """Test parsing CVE format with multiple vulnerabilities."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(5, len(findings))
```

**Step 2: Run tests to verify they fail**

Run: `docker compose exec uwsgi python manage.py test unittests.tools.test_qualys_vmdr_parser -v2 --keepdb 2>&1 | head -50`
Expected: FAIL with "ModuleNotFoundError: No module named 'dojo.tools.qualys_vmdr.parser'"

**Step 3: Commit failing tests**

```bash
git add unittests/tools/test_qualys_vmdr_parser.py
git commit -m "test(parser): add failing tests for qualys_vmdr basic structure

TDD: Tests written before implementation.

Authored by T. Walker - DefectDojo"
```

---

## Task 5: Implement helpers.py

**Files:**
- Create: `dojo/tools/qualys_vmdr/helpers.py`

**Step 1: Write helpers.py with all utility functions**

```python
"""
Shared helper functions for the Qualys VMDR parser.

This module contains utility functions used by both the QID and CVE parsers
to ensure consistent behavior across input formats.
"""

from dateutil import parser as dateutil_parser

from dojo.models import Endpoint


SEVERITY_MAPPING = {
    "1": "Info",
    "2": "Low",
    "3": "Medium",
    "4": "High",
    "5": "Critical",
}


def map_qualys_severity(severity_value):
    """
    Map Qualys severity (1-5) to DefectDojo severity string.

    Qualys uses a numeric severity scale from 1-5. This function converts
    that to DefectDojo's categorical severity levels.

    Mapping:
        1 -> Info
        2 -> Low
        3 -> Medium
        4 -> High
        5 -> Critical
        Invalid/missing -> Info

    Args:
        severity_value: The Qualys severity value (can be int, string, or None)

    Returns:
        str: DefectDojo severity level ("Info", "Low", "Medium", "High", "Critical")

    """
    if severity_value is None:
        return "Info"
    severity_str = str(severity_value).strip()
    return SEVERITY_MAPPING.get(severity_str, "Info")


def build_severity_justification(severity_value):
    """
    Build severity justification string from Qualys severity.

    Preserves the original numeric severity in the severity_justification field
    so users can see the exact Qualys score that determined the severity level.

    Args:
        severity_value: The Qualys severity value (can be int, string, or None)

    Returns:
        str or None: "Qualys Severity: X" if valid, None otherwise

    """
    if severity_value is None:
        return None
    severity_str = str(severity_value).strip()
    if severity_str in SEVERITY_MAPPING:
        return f"Qualys Severity: {severity_str}"
    return None


def parse_qualys_date(date_string):
    """
    Parse Qualys date format into a Python date object.

    Qualys exports dates in format like "Feb 03, 2026 07:00 AM".
    This function extracts just the date portion for the finding's date field.

    Args:
        date_string: Qualys formatted date string, or None/empty string

    Returns:
        date or None: Python date object if parsing succeeds, None otherwise

    """
    if not date_string or date_string == "'-":
        return None
    try:
        return dateutil_parser.parse(date_string).date()
    except (ValueError, TypeError):
        return None


def truncate_title(title, max_length=150):
    """
    Truncate title to maximum length with ellipsis suffix.

    DefectDojo has a limit on title length. This function ensures titles
    fit within that limit while indicating truncation occurred.

    Args:
        title: The original title string, or None/empty string
        max_length: Maximum allowed length (default 150 characters)

    Returns:
        str: Original title if within limit, truncated with "..." if over,
             or "Qualys VMDR Finding" if title is empty/None

    """
    if not title:
        return "Qualys VMDR Finding"
    title = title.strip()
    if len(title) <= max_length:
        return title
    return title[: max_length - 3] + "..."


def build_description_qid(row):
    """
    Build a structured markdown description from QID format CSV row.

    Creates a formatted description containing all relevant vulnerability
    metadata. Each field is displayed as a bold label followed by its value.
    Empty/None fields are omitted from the output.

    Args:
        row: Dictionary containing CSV row data

    Returns:
        str: Markdown-formatted description with all non-empty fields

    """
    parts = []

    title = row.get("Title", "")
    if title:
        parts.append(f"**Title:** {title}")

    qid = row.get("QID", "")
    if qid:
        parts.append(f"**QID:** {qid}")

    category = row.get("Category", "")
    if category:
        parts.append(f"**Category:** {category}")

    threat = row.get("Threat", "")
    if threat:
        parts.append(f"**Threat:** {threat}")

    rti = row.get("RTI", "")
    if rti:
        parts.append(f"**RTI:** {rti}")

    os_info = row.get("Operating System", "")
    if os_info:
        parts.append(f"**Operating System:** {os_info}")

    results = row.get("Results", "")
    if results:
        parts.append(f"**Results:** {results}")

    last_detected = row.get("Last Detected", "")
    if last_detected:
        parts.append(f"**Last Detected:** {last_detected}")

    return "\n\n".join(parts) if parts else "No details available."


def build_description_cve(row):
    """
    Build a structured markdown description from CVE format CSV row.

    Creates a formatted description containing all relevant vulnerability
    metadata including CVE-specific fields. Each field is displayed as a
    bold label followed by its value. Empty/None fields are omitted.

    Args:
        row: Dictionary containing CSV row data

    Returns:
        str: Markdown-formatted description with all non-empty fields

    """
    parts = []

    cve = row.get("CVE", "")
    if cve:
        parts.append(f"**CVE:** {cve}")

    cve_desc = row.get("CVE-Description", "")
    if cve_desc:
        parts.append(f"**CVE Description:** {cve_desc}")

    title = row.get("Title", "")
    if title:
        parts.append(f"**Title:** {title}")

    qid = row.get("QID", "")
    if qid:
        parts.append(f"**QID:** {qid}")

    category = row.get("Category", "")
    if category:
        parts.append(f"**Category:** {category}")

    threat = row.get("Threat", "")
    if threat:
        parts.append(f"**Threat:** {threat}")

    rti = row.get("RTI", "")
    if rti:
        parts.append(f"**RTI:** {rti}")

    os_info = row.get("Operating System", "")
    if os_info:
        parts.append(f"**Operating System:** {os_info}")

    results = row.get("Results", "")
    if results:
        parts.append(f"**Results:** {results}")

    last_detected = row.get("Last Detected", "")
    if last_detected:
        parts.append(f"**Last Detected:** {last_detected}")

    return "\n\n".join(parts) if parts else "No details available."


def parse_endpoints(ipv4_field, ipv6_field):
    """
    Parse IP addresses and return list of Endpoint objects.

    Handles comma-separated IP addresses in the IPv4 field and falls back
    to IPv6 if IPv4 is empty.

    Args:
        ipv4_field: Comma-separated IPv4 addresses, or empty string
        ipv6_field: IPv6 address, or empty string

    Returns:
        list[Endpoint]: List of Endpoint objects, one per IP address

    """
    endpoints = []

    if ipv4_field and ipv4_field.strip():
        ips = [ip.strip() for ip in ipv4_field.split(",") if ip.strip()]
        for ip in ips:
            endpoints.append(Endpoint(host=ip))
    elif ipv6_field and ipv6_field.strip():
        endpoints.append(Endpoint(host=ipv6_field.strip()))

    return endpoints


def parse_tags(tags_field):
    """
    Split comma-separated tags into a list.

    Args:
        tags_field: Comma-separated tag string, or None/empty string

    Returns:
        list[str]: List of individual tags, empty list if no tags

    """
    if not tags_field or not tags_field.strip():
        return []
    return [tag.strip() for tag in tags_field.split(",") if tag.strip()]


def parse_cvss_score(cvss_field):
    """
    Parse CVSS score field to float.

    Args:
        cvss_field: CVSS score string (e.g., "9.8"), or None/empty

    Returns:
        float or None: Parsed CVSS score, None if invalid or empty

    """
    if not cvss_field or cvss_field == "'-":
        return None
    try:
        return float(cvss_field)
    except (ValueError, TypeError):
        return None
```

**Step 2: Verify linting passes**

Run: `ruff check dojo/tools/qualys_vmdr/helpers.py`
Expected: No errors

**Step 3: Commit**

```bash
git add dojo/tools/qualys_vmdr/helpers.py
git commit -m "feat(parser): add helpers module for qualys_vmdr

Shared utilities for severity mapping, date parsing, description
building, endpoint parsing, and tag handling.

Authored by T. Walker - DefectDojo"
```

---

## Task 6: Implement qid_parser.py

**Files:**
- Create: `dojo/tools/qualys_vmdr/qid_parser.py`

**Step 1: Write QID format parser**

```python
"""
QID format parser for Qualys VMDR exports.

This module handles the QID-centric CSV export format where the primary
identifier is the Qualys QID (vulnerability ID).
"""

import csv
import io

from dojo.models import Finding
from dojo.tools.qualys_vmdr.helpers import (
    build_description_qid,
    build_severity_justification,
    map_qualys_severity,
    parse_endpoints,
    parse_qualys_date,
    parse_tags,
    truncate_title,
)


class QualysVMDRQIDParser:

    """Parse Qualys VMDR QID format exports."""

    def parse(self, content):
        """
        Parse QID format CSV content and return findings.

        Args:
            content: String containing the full CSV content

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        findings = []

        lines = content.split("\n")
        if len(lines) < 4:
            return findings

        csv_content = "\n".join(lines[3:])
        reader = csv.DictReader(io.StringIO(csv_content))

        for row in reader:
            finding = self._create_finding(row)
            if finding:
                findings.append(finding)

        return findings

    def _create_finding(self, row):
        """
        Create a Finding object from a CSV row.

        Args:
            row: Dictionary containing CSV row data

        Returns:
            Finding: DefectDojo Finding object

        """
        title = truncate_title(row.get("Title", ""))
        severity = map_qualys_severity(row.get("Severity"))
        severity_justification = build_severity_justification(row.get("Severity"))

        finding = Finding(
            title=title,
            severity=severity,
            severity_justification=severity_justification,
            description=build_description_qid(row),
            mitigation=row.get("Solution", ""),
            impact=row.get("Threat", ""),
            unique_id_from_tool=row.get("QID", ""),
            date=parse_qualys_date(row.get("First Detected")),
            active=(row.get("Status", "").upper() == "ACTIVE"),
            component_name=row.get("Asset Name", ""),
            service=row.get("Category", ""),
            static_finding=True,
            dynamic_finding=False,
        )

        finding.unsaved_endpoints = parse_endpoints(
            row.get("Asset IPV4", ""),
            row.get("Asset IPV6", ""),
        )
        finding.unsaved_tags = parse_tags(row.get("Asset Tags", ""))

        return finding
```

**Step 2: Verify linting passes**

Run: `ruff check dojo/tools/qualys_vmdr/qid_parser.py`
Expected: No errors

**Step 3: Commit**

```bash
git add dojo/tools/qualys_vmdr/qid_parser.py
git commit -m "feat(parser): add QID format parser for qualys_vmdr

Parses QID-centric CSV exports from Qualys VMDR.

Authored by T. Walker - DefectDojo"
```

---

## Task 7: Implement cve_parser.py

**Files:**
- Create: `dojo/tools/qualys_vmdr/cve_parser.py`

**Step 1: Write CVE format parser**

```python
"""
CVE format parser for Qualys VMDR exports.

This module handles the CVE-centric CSV export format where findings
include CVE identifiers and CVSS scores from NVD.
"""

import csv
import io

from dojo.models import Finding
from dojo.tools.qualys_vmdr.helpers import (
    build_description_cve,
    build_severity_justification,
    map_qualys_severity,
    parse_cvss_score,
    parse_endpoints,
    parse_qualys_date,
    parse_tags,
    truncate_title,
)


class QualysVMDRCVEParser:

    """Parse Qualys VMDR CVE format exports."""

    def parse(self, content):
        """
        Parse CVE format CSV content and return findings.

        Args:
            content: String containing the full CSV content

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        findings = []

        lines = content.split("\n")
        if len(lines) < 4:
            return findings

        csv_content = "\n".join(lines[3:])
        reader = csv.DictReader(io.StringIO(csv_content))

        for row in reader:
            finding = self._create_finding(row)
            if finding:
                findings.append(finding)

        return findings

    def _create_finding(self, row):
        """
        Create a Finding object from a CSV row.

        Args:
            row: Dictionary containing CSV row data

        Returns:
            Finding: DefectDojo Finding object

        """
        title = truncate_title(row.get("Title", ""))
        severity = map_qualys_severity(row.get("Severity"))
        severity_justification = build_severity_justification(row.get("Severity"))

        finding = Finding(
            title=title,
            severity=severity,
            severity_justification=severity_justification,
            description=build_description_cve(row),
            mitigation=row.get("Solution", ""),
            impact=row.get("Threat", ""),
            unique_id_from_tool=row.get("QID", ""),
            vuln_id_from_tool=row.get("CVE", ""),
            date=parse_qualys_date(row.get("First Detected")),
            active=(row.get("Status", "").upper() == "ACTIVE"),
            component_name=row.get("Asset Name", ""),
            service=row.get("Category", ""),
            static_finding=True,
            dynamic_finding=False,
        )

        cvss_score = parse_cvss_score(row.get("CVSSv3.1 Base (nvd)"))
        if cvss_score is not None:
            finding.cvssv3_score = cvss_score

        finding.unsaved_endpoints = parse_endpoints(
            row.get("Asset IPV4", ""),
            row.get("Asset IPV6", ""),
        )
        finding.unsaved_tags = parse_tags(row.get("Asset Tags", ""))

        return finding
```

**Step 2: Verify linting passes**

Run: `ruff check dojo/tools/qualys_vmdr/cve_parser.py`
Expected: No errors

**Step 3: Commit**

```bash
git add dojo/tools/qualys_vmdr/cve_parser.py
git commit -m "feat(parser): add CVE format parser for qualys_vmdr

Parses CVE-centric CSV exports with CVSS scores from NVD.

Authored by T. Walker - DefectDojo"
```

---

## Task 8: Implement Main parser.py

**Files:**
- Create: `dojo/tools/qualys_vmdr/parser.py`

**Step 1: Write main parser with format detection**

```python
"""
Qualys VMDR parser for DefectDojo.

Qualys VMDR (Vulnerability Management, Detection, and Response) provides
comprehensive vulnerability assessment and management. This parser imports
Qualys VMDR exports in CSV format (QID or CVE variants).

For more information about Qualys VMDR, see:
https://www.qualys.com/apps/vulnerability-management-detection-response/
"""

from dojo.tools.qualys_vmdr.cve_parser import QualysVMDRCVEParser
from dojo.tools.qualys_vmdr.qid_parser import QualysVMDRQIDParser


class QualysVMDRParser:

    """Parser for Qualys VMDR vulnerability exports (CSV format)."""

    def get_scan_types(self):
        """Return the scan type identifier for this parser."""
        return ["Qualys VMDR"]

    def get_label_for_scan_types(self, scan_type):
        """Return the human-readable label for this scan type."""
        return "Qualys VMDR"

    def get_description_for_scan_types(self, scan_type):
        """Return the description shown in the DefectDojo UI."""
        return "Import Qualys VMDR vulnerability exports (CSV format, QID or CVE)."

    def get_findings(self, filename, test):
        """
        Parse a Qualys VMDR export file and return findings.

        This method auto-detects the file format (QID vs CVE) by examining
        the CSV header row. QID format has "QID" as the first column, while
        CVE format has "CVE" as the first column.

        Args:
            filename: File-like object containing the Qualys VMDR export
            test: DefectDojo Test object to associate findings with

        Returns:
            list[Finding]: List of DefectDojo Finding objects

        """
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        lines = content.split("\n")
        if len(lines) < 4:
            return []

        header_line = lines[3]

        if header_line.startswith('"CVE,') or header_line.startswith("CVE,"):
            return QualysVMDRCVEParser().parse(content)
        return QualysVMDRQIDParser().parse(content)
```

**Step 2: Verify linting passes**

Run: `ruff check dojo/tools/qualys_vmdr/parser.py`
Expected: No errors

**Step 3: Run tests to verify basic tests pass**

Run: `docker compose exec uwsgi python manage.py test unittests.tools.test_qualys_vmdr_parser -v2 --keepdb`
Expected: All 10 tests pass

**Step 4: Commit**

```bash
git add dojo/tools/qualys_vmdr/parser.py
git commit -m "feat(parser): add main qualys_vmdr parser with format detection

Auto-detects QID vs CVE format and delegates to appropriate parser.

Authored by T. Walker - DefectDojo"
```

---

## Task 9: Add Field Validation Tests

**Files:**
- Modify: `unittests/tools/test_qualys_vmdr_parser.py`

**Step 1: Add detailed field validation tests**

Append to the existing test file:

```python

    def test_qid_severity_mapping_critical(self):
        """Test severity 5 maps to Critical."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Critical", findings[0].severity)

    def test_qid_severity_justification(self):
        """Test severity justification preserves original score."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Qualys Severity: 5", findings[0].severity_justification)

    def test_qid_unique_id_from_tool(self):
        """Test QID is mapped to unique_id_from_tool."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("100269", findings[0].unique_id_from_tool)

    def test_qid_active_status(self):
        """Test ACTIVE status maps to active=True."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].active)

    def test_qid_fixed_status(self):
        """Test FIXED status maps to active=False."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            fixed_finding = [f for f in findings if f.unique_id_from_tool == "100003"][0]
            self.assertFalse(fixed_finding.active)

    def test_qid_component_name(self):
        """Test Asset Name maps to component_name."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("TESTSERVER01", findings[0].component_name)

    def test_qid_service(self):
        """Test Category maps to service."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("Internet Explorer", findings[0].service)

    def test_qid_endpoints_single_ip(self):
        """Test single IP creates one endpoint."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            endpoints = findings[0].unsaved_endpoints
            self.assertEqual(1, len(endpoints))
            self.assertEqual("10.0.0.1", endpoints[0].host)

    def test_qid_endpoints_multiple_ips(self):
        """Test comma-separated IPs create multiple endpoints."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            multi_ip_finding = [f for f in findings if f.unique_id_from_tool == "100003"][0]
            endpoints = multi_ip_finding.unsaved_endpoints
            self.assertEqual(2, len(endpoints))
            hosts = [e.host for e in endpoints]
            self.assertIn("10.0.0.20", hosts)
            self.assertIn("10.0.0.21", hosts)

    def test_qid_endpoints_ipv6_fallback(self):
        """Test IPv6 is used when IPv4 is empty."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            ipv6_finding = [f for f in findings if f.unique_id_from_tool == "100005"][0]
            endpoints = ipv6_finding.unsaved_endpoints
            self.assertEqual(1, len(endpoints))
            self.assertEqual("2001:db8::1", endpoints[0].host)

    def test_qid_tags(self):
        """Test Asset Tags are parsed into unsaved_tags."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            tags = findings[0].unsaved_tags
            self.assertIn("Server", tags)
            self.assertIn("Production", tags)

    def test_qid_static_dynamic_flags(self):
        """Test static_finding=True and dynamic_finding=False."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertTrue(findings[0].static_finding)
            self.assertFalse(findings[0].dynamic_finding)

    def test_qid_severity_mapping_all_levels(self):
        """Test all severity levels are correctly mapped."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "many_vulns_qid.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            severity_map = {f.unique_id_from_tool: f.severity for f in findings}
            self.assertEqual("Info", severity_map["100001"])
            self.assertEqual("Low", severity_map["100002"])
            self.assertEqual("Medium", severity_map["100003"])
            self.assertEqual("High", severity_map["100004"])
            self.assertEqual("Critical", severity_map["100005"])

    def test_cve_vuln_id_from_tool(self):
        """Test CVE is mapped to vuln_id_from_tool."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("CVE-2021-44228", findings[0].vuln_id_from_tool)

    def test_cve_unique_id_from_tool(self):
        """Test QID is still mapped to unique_id_from_tool in CVE format."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual("730143", findings[0].unique_id_from_tool)

    def test_cve_cvssv3_score(self):
        """Test CVSSv3.1 Base score is parsed."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(10.0, findings[0].cvssv3_score)

    def test_cve_description_includes_cve_info(self):
        """Test CVE format description includes CVE details."""
        with (get_unit_tests_scans_path("qualys_vmdr") / "one_vuln_cve.csv").open(
            encoding="utf-8"
        ) as testfile:
            parser = QualysVMDRParser()
            findings = parser.get_findings(testfile, Test())
            description = findings[0].description
            self.assertIn("CVE-2021-44228", description)
            self.assertIn("Log4j", description)
```

**Step 2: Run all tests**

Run: `docker compose exec uwsgi python manage.py test unittests.tools.test_qualys_vmdr_parser -v2 --keepdb`
Expected: All tests pass (should be ~27 tests now)

**Step 3: Commit**

```bash
git add unittests/tools/test_qualys_vmdr_parser.py
git commit -m "test(parser): add field validation tests for qualys_vmdr

Comprehensive tests for severity mapping, endpoints, tags, CVE fields.

Authored by T. Walker - DefectDojo"
```

---

## Task 10: Run Linter and Fix Issues

**Step 1: Run ruff on all parser files**

Run: `ruff check dojo/tools/qualys_vmdr/`
Expected: No errors (if errors, fix them)

**Step 2: Run ruff on test file**

Run: `ruff check unittests/tools/test_qualys_vmdr_parser.py`
Expected: No errors (if errors, fix them)

**Step 3: Commit any fixes (if needed)**

```bash
git add dojo/tools/qualys_vmdr/ unittests/tools/test_qualys_vmdr_parser.py
git commit -m "style(parser): fix linting issues in qualys_vmdr

Authored by T. Walker - DefectDojo"
```

---

## Task 11: Create Documentation

**Files:**
- Create: `docs/content/supported_tools/parsers/file/qualys_vmdr.md`

**Step 1: Write documentation following enhanced format structure**

```markdown
---
title: "Qualys VMDR"
toc_hide: true
---

The [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/) parser for DefectDojo supports imports from CSV format. This parser handles both QID-centric and CVE-centric export variants from Qualys VMDR (Vulnerability Management, Detection, and Response).

## Supported File Types

The Qualys VMDR parser accepts CSV file format in two variants:

**QID Format:** Primary vulnerability identifier is the Qualys QID
**CVE Format:** Includes CVE identifiers and CVSS scores from NVD

To generate these files from Qualys VMDR:

1. Log into your Qualys VMDR console
2. Navigate to Vulnerabilities > Vulnerability Management
3. Select the assets or vulnerabilities to export
4. Click "Download" and select CSV format
5. Choose either QID-centric or CVE-centric export option
6. Upload the downloaded CSV file to DefectDojo

## Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- unique_id_from_tool (QID)

### Sample Scan Data

Sample Qualys VMDR scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/qualys_vmdr).

## Link To Tool

- [Qualys VMDR](https://www.qualys.com/apps/vulnerability-management-detection-response/)
- [Qualys Documentation](https://www.qualys.com/documentation/)

## QID Format (Primary Export)

### Total Fields in QID CSV

- Total data fields: 41
- Total data fields parsed: 14
- Total data fields NOT parsed: 27

### QID Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser File | Notes |
| ------------ | ---------------- | ----------- | ----- |
| Title | title | qid_parser.py | Truncated to 150 characters |
| Severity | severity | qid_parser.py | Mapped: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | severity_justification | qid_parser.py | Preserved as "Qualys Severity: X" |
| QID | unique_id_from_tool | qid_parser.py | Qualys vulnerability identifier for deduplication |
| First Detected | date | qid_parser.py | Parsed to date object |
| Status | active | qid_parser.py | True if "ACTIVE", False otherwise |
| Solution | mitigation | qid_parser.py | Remediation guidance |
| Threat | impact | qid_parser.py | Threat description |
| Asset Name | component_name | qid_parser.py | Asset/server name |
| Category | service | qid_parser.py | Vulnerability category |
| Asset IPV4 | unsaved_endpoints | qid_parser.py | Multiple endpoints if comma-separated |
| Asset IPV6 | unsaved_endpoints | qid_parser.py | Fallback if no IPv4 |
| Asset Tags | unsaved_tags | qid_parser.py | Split on comma |
| Results | description | qid_parser.py | Included in description |

</details>

### Additional Finding Field Settings (QID Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser File | Notes |
|---------------|---------------|-------------|-------|
| static_finding | True | qid_parser.py | Vulnerability scan data |
| dynamic_finding | False | qid_parser.py | Not dynamic testing |

</details>

## CVE Format (Extended Export)

### Total Fields in CVE CSV

- Total data fields: 41
- Total data fields parsed: 17
- Total data fields NOT parsed: 24

### CVE Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field | DefectDojo Field | Parser File | Notes |
| ------------ | ---------------- | ----------- | ----- |
| CVE | vuln_id_from_tool | cve_parser.py | CVE identifier (e.g., CVE-2021-44228) |
| CVE-Description | description | cve_parser.py | Prepended to description |
| CVSSv3.1 Base (nvd) | cvssv3_score | cve_parser.py | Numeric CVSS score |
| Title | title | cve_parser.py | Truncated to 150 characters |
| Severity | severity | cve_parser.py | Mapped: 1=Info, 2=Low, 3=Medium, 4=High, 5=Critical |
| Severity | severity_justification | cve_parser.py | Preserved as "Qualys Severity: X" |
| QID | unique_id_from_tool | cve_parser.py | Qualys vulnerability identifier for deduplication |
| First Detected | date | cve_parser.py | Parsed to date object |
| Status | active | cve_parser.py | True if "ACTIVE", False otherwise |
| Solution | mitigation | cve_parser.py | Remediation guidance |
| Threat | impact | cve_parser.py | Threat description |
| Asset Name | component_name | cve_parser.py | Asset/server name |
| Category | service | cve_parser.py | Vulnerability category |
| Asset IPV4 | unsaved_endpoints | cve_parser.py | Multiple endpoints if comma-separated |
| Asset IPV6 | unsaved_endpoints | cve_parser.py | Fallback if no IPv4 |
| Asset Tags | unsaved_tags | cve_parser.py | Split on comma |
| Results | description | cve_parser.py | Included in description |

</details>

### Additional Finding Field Settings (CVE Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field | Default Value | Parser File | Notes |
|---------------|---------------|-------------|-------|
| static_finding | True | cve_parser.py | Vulnerability scan data |
| dynamic_finding | False | cve_parser.py | Not dynamic testing |

</details>

## Special Processing Notes

### Date Processing

The parser uses dateutil.parser to handle Qualys date formats (e.g., "Feb 03, 2026 07:00 AM"). The First Detected field is used for the finding date.

### Severity Conversion

Qualys severity levels (1-5 numeric scale) are converted to DefectDojo severity levels:
- `1` → Info
- `2` → Low
- `3` → Medium
- `4` → High
- `5` → Critical

The original Qualys severity is preserved in the severity_justification field as "Qualys Severity: X".

### Description Construction

The parser combines multiple fields to create a comprehensive markdown description:
- Title
- QID
- Category
- Threat
- RTI (Real-Time Intelligence)
- Operating System
- Results
- Last Detected

For CVE format, the description also includes:
- CVE identifier
- CVE Description from NVD

### Title Format

Finding titles use the vulnerability name directly from the Title field, truncated to 150 characters with "..." suffix if longer.

### Endpoint Handling

The parser creates Endpoint objects from IP addresses:
- Multiple IPv4 addresses (comma-separated) create multiple endpoints
- Falls back to IPv6 if no IPv4 address is present
- Each endpoint represents an affected asset

### Deduplication

DefectDojo uses the `unique_id_from_tool` field populated with the Qualys QID for deduplication. This ensures the same vulnerability type is deduplicated within an asset's scope.

### Tags Handling

Asset Tags are extracted and split by commas. Each tag is added to the finding's unsaved_tags list for categorization and filtering in DefectDojo.

### Format Detection

The parser automatically detects whether the import file is QID format or CVE format by examining the first column of the header row:
- If first column is "QID" → QID format parser is used
- If first column is "CVE" → CVE format parser is used
```

**Step 2: Verify documentation file created**

Run: `ls -la docs/content/supported_tools/parsers/file/qualys_vmdr.md`
Expected: Shows the file exists

**Step 3: Commit**

```bash
git add docs/content/supported_tools/parsers/file/qualys_vmdr.md
git commit -m "docs(parser): add qualys_vmdr parser documentation

Includes field mapping tables, severity conversion, and processing notes.

Authored by T. Walker - DefectDojo"
```

---

## Task 12: Final Verification

**Step 1: Run full test suite**

Run: `docker compose exec uwsgi python manage.py test unittests.tools.test_qualys_vmdr_parser -v2 --keepdb`
Expected: All tests pass

**Step 2: Run linter on all files**

Run: `ruff check dojo/tools/qualys_vmdr/ unittests/tools/test_qualys_vmdr_parser.py`
Expected: No errors

**Step 3: Create Test_Type in database**

Run: `docker compose exec uwsgi python manage.py shell -c "from dojo.models import Test_Type; Test_Type.objects.get_or_create(name='Qualys VMDR')"`
Expected: Shows tuple with Test_Type object and created boolean

**Step 4: Restart uwsgi to pick up new parser**

Run: `docker compose restart uwsgi`
Expected: Container restarts successfully

**Step 5: Verify parser appears in UI**

Open: http://localhost:8080 and navigate to Import Scan
Expected: "Qualys VMDR" appears in scan type dropdown

**Step 6: Test with real data (optional)**

If you have the customer data files, test importing them through the UI to verify real-world functionality.

---

## Task 13: Push to Remote for Review

**Step 1: Review all commits**

Run: `git log --oneline dev..HEAD`
Expected: Shows all commits for this feature

**Step 2: Push to fork**

Run: `git push -u origin qualys-vmdr-parser`
Expected: Branch pushed to origin

**Step 3: Verify on GitHub**

Open: https://github.com/skywalke34/django-DefectDojo/tree/qualys-vmdr-parser
Expected: Branch visible with all files

---

## Summary

This plan creates a complete Qualys VMDR parser following TDD principles:

1. **Package structure** - Empty `__init__.py`
2. **Test files** - 6 CSV files covering both formats
3. **Failing tests** - Written before implementation
4. **helpers.py** - Shared utilities for both parsers
5. **qid_parser.py** - QID format parsing
6. **cve_parser.py** - CVE format parsing
7. **parser.py** - Main dispatcher with format detection
8. **Field validation tests** - Comprehensive test coverage
9. **Linting** - All files pass ruff
10. **Documentation** - Following enhanced format structure
11. **Final verification** - Tests pass, UI works
12. **Push for review** - Ready for PR
