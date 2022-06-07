from os import path
import datetime
from ..dojo_test_case import DojoTestCase, get_unit_tests_path

from dojo.models import Test, Finding
from dojo.tools.sarif.parser import SarifParser


class TestSarifParser(DojoTestCase):
    def common_checks(self, finding):
        self.assertLessEqual(len(finding.title), 250)
        self.assertIn(finding.severity, Finding.SEVERITIES)
        if finding.cve:
            self.assertIsInstance(finding.cve, str)
        if finding.cwe:
            self.assertIsInstance(finding.cwe, int)
        self.assertEqual(True, finding.static_finding)  # by specification
        self.assertEqual(False, finding.dynamic_finding)  # by specification

    def test_example_report(self):
        testfile = open(
            path.join(
                get_unit_tests_path() + "/scans/sarif/DefectDojo_django-DefectDojo__2020-12-11_13 42 10__export.sarif"
            )
        )
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(510, len(findings))
        for finding in findings:
            self.common_checks(finding)

    def test_example2_report(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/appendix_k.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual("collections/list.h", item.file_path)
        self.assertEqual(15, item.line)
        self.assertEqual("Critical", item.severity)
        description = """**Result message:** Variable "ptr" was used without being initialized. It was declared [here](0).
**Snippet:**
```add_core(ptr, offset, val);
    return;```
**Rule short description:** A variable was used without being initialized.
**Rule full description:** A variable was used without being initialized. This can result in runtime errors such as null reference exceptions."""
        self.assertEqual(description, item.description)
        self.assertEqual(datetime.datetime(2016, 7, 16, 14, 19, 1, tzinfo=datetime.timezone.utc), item.date)
        for finding in findings:
            self.common_checks(finding)

    def test_example_k1_report(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/appendix_k1.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(0, len(findings))

    def test_example_k2_report(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/appendix_k2.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual('Variable "count" was used without being initialized.', item.title)
        self.assertEqual("src/collections/list.cpp", item.file_path)
        self.assertEqual(15, item.line)
        description = """**Result message:** Variable "count" was used without being initialized.
**Rule full description:** A variable was used without being initialized. This can result in runtime errors such as null reference exceptions."""
        self.assertEquals(description, item.description)
        for finding in findings:
            self.common_checks(finding)

    def test_example_k3_report(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/appendix_k3.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        item = findings[0]
        self.assertEqual('The insecure method "Crypto.Sha1.Encrypt" should not be used.', item.title)
        for finding in findings:
            self.common_checks(finding)

    def test_example_k4_report_mitigation(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/appendix_k4.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(1, len(findings))
        for finding in findings:
            self.common_checks(finding)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual(
                'Variable "ptr" was used without being initialized. It was declared [here](0).', finding.title
            )
            self.assertEqual("C2001", finding.vuln_id_from_tool)
            self.assertEqual("collections/list.h", finding.file_path)
            self.assertEqual("Initialize the variable to null", finding.mitigation)

    def test_example_report_ms(self):
        """Report file come from Microsoft SARIF sdk on GitHub"""
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/SuppressionTestCurrent.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        item = findings[0]
        self.assertEqual("New suppressed result.", item.title)
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_semgrep(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/semgrepowasp-benchmark-sample.sarif"))
        test = Test()
        parser = SarifParser()
        findings = parser.get_findings(testfile, test)
        self.assertEqual(1768, len(findings))
        item = findings[0]
        self.assertEqual(
            "src/main/java/org/owasp/benchmark/testcode/BenchmarkTest02660.java",
            item.file_path,
        )
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_scanlift_dependency_check(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/dependency_check.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(13, len(findings))
        # finding 0
        item = findings[0]
        self.assertEqual(
            "file:////src/.venv/lib/python3.9/site-packages/tastypie_swagger/static/tastypie_swagger/js/lib/handlebars-1.0.0.js",
            item.file_path,
        )
        # finding 6
        item = findings[6]
        self.assertEqual(
            "CVE-2019-11358 - jQuery before 3.4.0, as used in Drupal, Backdrop CMS, and other products, mishandles jQuery.extend(true, {}, ...) because of [...]",
            item.title,
        )
        self.assertEqual("Critical", item.severity)
        self.assertEqual("CVE-2019-11358", item.cve)
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_scanlift_bash(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/bash-report.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(27, len(findings))
        # finding 0
        item = findings[0]
        self.assertEqual(
            "file:///home/damien/dd/docker/setEnv.sh",
            item.file_path,
        )
        self.assertIsNone(item.cve)
        self.assertEqual(datetime.datetime(2021, 3, 8, 15, 39, 40, tzinfo=datetime.timezone.utc), item.date)
        # finding 6
        item = findings[6]
        self.assertEqual(
            "Decimals are not supported. Either use integers only, or use bc or awk to compare.",
            item.title,
        )
        self.assertEqual("Info", item.severity)
        self.assertIsNone(item.cve)
        for finding in findings:
            self.common_checks(finding)

    def test_example_report_taint_python(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/taint-python-report.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(11, len(findings))
        # finding 0
        item = findings[0]
        self.assertEqual(
            "file:///home/damien/dd/dojo/tools/veracode/parser.py",
            item.file_path,
        )
        self.assertIsNone(item.cve)
        self.assertEqual(datetime.datetime(2021, 3, 8, 15, 46, 16, tzinfo=datetime.timezone.utc), item.date)
        # finding 2
        item = findings[2]
        self.assertEqual(
            "file:///home/damien/dd/dojo/tools/qualys_infrascan_webgui/parser.py",
            item.file_path,
        )
        self.assertEqual(169, item.line)
        # finding 6
        item = findings[6]
        self.assertEqual(
            "XML injection with user data from `filename in parser_helper.py:167` is used for parsing XML at `parser_helper.py:23`.",
            item.title,
        )
        self.assertEqual("Critical", item.severity)
        self.assertIsNone(item.cve)
        for finding in findings:
            self.common_checks(finding)

    def test_njsscan(self):
        """Generated with opensecurity/njsscan (https://github.com/ajinabraham/njsscan)"""
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/njsscan.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(2, len(findings))
        # finding 0
        finding = findings[0]
        self.assertEqual(
            "file:///src/index.js",
            finding.file_path,
        )
        self.assertIsNone(finding.cve)
        self.assertEqual(datetime.datetime(2021, 3, 23, 0, 10, 48, tzinfo=datetime.timezone.utc), finding.date)
        self.assertEqual(327, finding.cwe)
        # finding 1
        finding = findings[1]
        self.assertEqual(
            "file:///src/index.js",
            finding.file_path,
        )
        self.assertEqual(235, finding.line)
        self.assertEqual(datetime.datetime(2021, 3, 23, 0, 10, 48, tzinfo=datetime.timezone.utc), finding.date)
        self.assertEqual(798, finding.cwe)
        for finding in findings:
            self.common_checks(finding)

    def test_dockle(self):
        """Generated with goodwithtech/dockle (https://github.com/goodwithtech/dockle)"""
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/dockle_0_3_15.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(4, len(findings))
        for finding in findings:
            self.common_checks(finding)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("CIS-DI-0010", finding.vuln_id_from_tool)
            self.assertEqual("Critical", finding.severity)
            description = """**Result message:** Suspicious ENV key found : DD_ADMIN_PASSWORD, Suspicious ENV key found : DD_CELERY_BROKER_PASSWORD, Suspicious ENV key found : DD_DATABASE_PASSWORD
**Rule short description:** Do not store credential in ENVIRONMENT vars/files"""
            self.assertEqual(description, finding.description)
            self.assertEqual(
                "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0010", finding.references
            )
        with self.subTest(i=1):
            finding = findings[1]
            self.assertEqual("CIS-DI-0005", finding.vuln_id_from_tool)
            self.assertEqual("Info", finding.severity)
            description = """**Result message:** export DOCKER_CONTENT_TRUST=1 before docker pull/build
**Rule short description:** Enable Content trust for Docker"""
            self.assertEqual(description, finding.description)
            self.assertEqual(
                "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0005", finding.references
            )
        with self.subTest(i=2):
            finding = findings[2]
            self.assertEqual("CIS-DI-0006", finding.vuln_id_from_tool)
            self.assertEqual("Info", finding.severity)
            description = """**Result message:** not found HEALTHCHECK statement
**Rule short description:** Add HEALTHCHECK instruction to the container image"""
            self.assertEqual(description, finding.description)
            self.assertEqual(
                "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0006", finding.references
            )
        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("CIS-DI-0008", finding.vuln_id_from_tool)
            self.assertEqual("Info", finding.severity)
            description = """**Result message:** setuid file: urwxr-xr-x usr/bin/chfn, setuid file: urwxr-xr-x usr/bin/chsh, setuid file: urwxr-xr-x usr/bin/passwd, setuid file: urwxr-xr-x bin/umount, setuid file: urwxr-xr-x bin/mount, setgid file: grwxr-xr-x usr/bin/wall, setgid file: grwxr-xr-x usr/bin/expiry, setuid file: urwxr-xr-x bin/su, setgid file: grwxr-xr-x sbin/unix_chkpwd, setuid file: urwxr-xr-x usr/bin/gpasswd, setgid file: grwxr-xr-x usr/bin/chage, setuid file: urwxr-xr-x usr/bin/newgrp
**Rule short description:** Confirm safety of setuid/setgid files"""
            self.assertEqual(description, finding.description)
            self.assertEqual(
                "https://github.com/goodwithtech/dockle/blob/master/CHECKPOINT.md#CIS-DI-0008", finding.references
            )

    def test_mobsfscan(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/mobsfscan.json"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(9, len(findings))
        for finding in findings:
            self.common_checks(finding)

    def test_gitleaks(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/gitleaks_7.5.0.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(8, len(findings))
        for finding in findings:
            self.common_checks(finding)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("AWS Access Key secret detected", finding.title)
            self.assertEqual("Medium", finding.severity)
            description = """**Result message:** AWS Access Key secret detected
**Snippet:**
```      \"raw_source_code_extract\": \"AKIAIOSFODNN7EXAMPLE\",```"""
            self.assertEqual(description, finding.description)
            self.assertEqual(
                "dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_1_vuln.json",
                finding.file_path,
            )
            self.assertEqual(13, finding.line)
        with self.subTest(i=3):
            finding = findings[3]
            self.assertEqual("AWS Access Key secret detected", finding.title)
            self.assertEqual("Medium", finding.severity)
            description = """**Result message:** AWS Access Key secret detected
**Snippet:**
```      \"raw_source_code_extract\": \"AKIAIOSFODNN7EXAMPLE\",```"""
            self.assertEqual(description, finding.description)
            self.assertEqual(
                "dojo/unittests/scans/gitlab_secret_detection_report/gitlab_secret_detection_report_3_vuln.json",
                finding.file_path,
            )
            self.assertEqual(44, finding.line)
        with self.subTest(i=7):
            finding = findings[7]
            self.assertEqual("AWS Access Key secret detected", finding.title)
            self.assertEqual("Medium", finding.severity)
            description = """**Result message:** AWS Access Key secret detected
**Snippet:**
```        self.assertEqual(\"AWS\\nAKIAIOSFODNN7EXAMPLE\", first_finding.description)```"""
            self.assertEqual(description, finding.description)
            self.assertEqual("dojo/unittests/tools/test_gitlab_secret_detection_report_parser.py", finding.file_path)
            self.assertEqual(37, finding.line)

    def test_flawfinder(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/flawfinder.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(53, len(findings))
        for finding in findings:
            self.common_checks(finding)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual(
                "random/setstate:This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327).",
                finding.title,
            )
            self.assertEqual("Critical", finding.severity)
            description = """**Result message:** random/setstate:This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327).
**Snippet:**
```      is.setstate(std::ios::failbit);```
**Rule name:** random/setstate
**Rule short description:** This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327)."""
            self.assertEqual(description, finding.description)
            self.assertEqual("src/tree/param.cc", finding.file_path)
            self.assertEqual(29, finding.line)
            self.assertEqual(327, finding.cwe)
            self.assertEqual("FF1048", finding.vuln_id_from_tool)
            self.assertEqual("https://cwe.mitre.org/data/definitions/327.html", finding.references)
        with self.subTest(i=20):
            finding = findings[20]
            self.assertEqual(
                "buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).",
                finding.title,
            )
            self.assertEqual("Info", finding.severity)
            description = """**Result message:** buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).
**Snippet:**
```    std::memcpy(dptr, dmlc::BeginPtr(buffer_) + buffer_ptr_, size);```
**Rule name:** buffer/memcpy
**Rule short description:** Does not check for buffer overflows when copying to destination (CWE-120)."""
            self.assertEqual(description, finding.description)
            self.assertEqual("src/common/io.cc", finding.file_path)
            self.assertEqual(31, finding.line)
            self.assertEqual(120, finding.cwe)
            self.assertEqual("FF1004", finding.vuln_id_from_tool)
            self.assertEqual("https://cwe.mitre.org/data/definitions/120.html", finding.references)
        with self.subTest(i=52):
            finding = findings[52]
            self.assertEqual(
                "buffer/sscanf:The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20).",
                finding.title,
            )
            self.assertEqual("Critical", finding.severity)
            description = """**Result message:** buffer/sscanf:The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20).
**Snippet:**
```      if (sscanf(argv[i], "%[^=]=%s", name, val) == 2) {```
**Rule name:** buffer/sscanf
**Rule short description:** The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20)."""
            self.assertEqual(description, finding.description)
            self.assertEqual("src/cli_main.cc", finding.file_path)
            self.assertEqual(482, finding.line)
            self.assertEqual("FF1021", finding.vuln_id_from_tool)
            self.assertEqual("https://cwe.mitre.org/data/definitions/120.html", finding.references)

    def test_flawfinder_interfacev2(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/flawfinder.sarif"))
        parser = SarifParser()
        tests = parser.get_tests(parser.get_scan_types()[0], testfile)
        self.assertEqual(1, len(tests))
        findings = tests[0].findings
        self.assertEqual(53, len(findings))
        for finding in findings:
            self.common_checks(finding)
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual(
                "random/setstate:This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327).",
                finding.title,
            )
            self.assertEqual("Critical", finding.severity)
            description = """**Result message:** random/setstate:This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327).
**Snippet:**
```      is.setstate(std::ios::failbit);```
**Rule name:** random/setstate
**Rule short description:** This function is not sufficiently random for security-related functions such as key and nonce creation (CWE-327)."""
            self.assertEqual(description, finding.description)
            self.assertEqual("src/tree/param.cc", finding.file_path)
            self.assertEqual(29, finding.line)
            self.assertEqual(327, finding.cwe)
            self.assertEqual("FF1048", finding.vuln_id_from_tool)
            self.assertEqual("https://cwe.mitre.org/data/definitions/327.html", finding.references)
        with self.subTest(i=20):
            finding = findings[20]
            self.assertEqual(
                "buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).",
                finding.title,
            )
            self.assertEqual("Info", finding.severity)
            description = """**Result message:** buffer/memcpy:Does not check for buffer overflows when copying to destination (CWE-120).
**Snippet:**
```    std::memcpy(dptr, dmlc::BeginPtr(buffer_) + buffer_ptr_, size);```
**Rule name:** buffer/memcpy
**Rule short description:** Does not check for buffer overflows when copying to destination (CWE-120)."""
            self.assertEqual(description, finding.description)
            self.assertEqual("src/common/io.cc", finding.file_path)
            self.assertEqual(31, finding.line)
            self.assertEqual(120, finding.cwe)
            self.assertEqual("FF1004", finding.vuln_id_from_tool)
            self.assertEqual('https://cwe.mitre.org/data/definitions/120.html', finding.references)
        with self.subTest(i=52):
            finding = findings[52]
            self.assertEqual("buffer/sscanf:The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20).", finding.title)
            self.assertEqual("Critical", finding.severity)
            description = """**Result message:** buffer/sscanf:The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20).
**Snippet:**
```      if (sscanf(argv[i], "%[^=]=%s", name, val) == 2) {```
**Rule name:** buffer/sscanf
**Rule short description:** The scanf() family's %s operation, without a limit specification, permits buffer overflows (CWE-120, CWE-20)."""
            self.assertEqual(description, finding.description)
            self.assertEqual("src/cli_main.cc", finding.file_path)
            self.assertEqual(482, finding.line)
            self.assertEqual("FF1021", finding.vuln_id_from_tool)
            self.assertEqual("https://cwe.mitre.org/data/definitions/120.html", finding.references)

    def test_appendix_k1_double_interfacev2(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/appendix_k1_double.sarif"))
        parser = SarifParser()
        tests = parser.get_tests(parser.get_scan_types()[0], testfile)
        self.assertEqual(2, len(tests))
        with self.subTest(test=0):
            test = tests[0]
            self.assertEqual("CodeScanner", test.type)
            findings = test.findings
            self.assertEqual(0, len(findings))
        with self.subTest(test=1):
            test = tests[1]
            self.assertEqual("OtherScanner", test.type)
            findings = test.findings
            self.assertEqual(0, len(findings))

    def test_codeql_snippet_report(self):
        testfile = open(path.join(path.dirname(__file__), "../scans/sarif/codeQL-output.sarif"))
        parser = SarifParser()
        findings = parser.get_findings(testfile, Test())
        self.assertEqual(72, len(findings))
        item = findings[7]
        self.assertEqual("good/mod_user.py", item.file_path)
        self.assertEqual(33, item.line)
        self.assertEqual("Critical", item.severity)
        description = """**Result message:** Keyword argument 'request' is not a supported parameter name of [function create](1).
**Snippet:**
```
        response = make_response(redirect('/'))
        response = libsession.create(request=request, response=response, username=username)
        return response

```
**Rule name:** py/call/wrong-named-argument
**Rule short description:** Wrong name for an argument in a call
**Rule full description:** Using a named argument whose name does not correspond to a parameter of the called function or method, will result in a TypeError at runtime."""
        self.assertEqual(description, item.description)
        for finding in findings:
            self.common_checks(finding)
