
from dojo.models import Test
from dojo.tools.zap.parser import ZapParser
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestZapParser(DojoTestCase):

    def test_parse_no_findings(self):
        with (get_unit_tests_scans_path("zap") / "empty_2.9.0.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(0, len(findings))

    def test_parse_some_findings(self):
        with (get_unit_tests_scans_path("zap") / "some_2.9.0.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(7, len(findings))
            self.validate_locations(findings)

    def test_parse_some_findings_0(self):
        with (get_unit_tests_scans_path("zap") / "0_zap_sample.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            self.validate_locations(findings)

    def test_parse_some_findings_1(self):
        with (get_unit_tests_scans_path("zap") / "1_zap_sample_0_and_new_absent.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            self.validate_locations(findings)

    def test_parse_some_findings_2(self):
        with (get_unit_tests_scans_path("zap") / "2_zap_sample_0_and_new_endpoint.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            self.validate_locations(findings)

    def test_parse_some_findings_3(self):
        with (get_unit_tests_scans_path("zap") / "3_zap_sampl_0_and_different_severities.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            self.validate_locations(findings)

    def test_parse_some_findings_5(self):
        with (get_unit_tests_scans_path("zap") / "5_zap_sample_one.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(2, len(findings))
            self.validate_locations(findings)

    def test_parse_issue4360(self):
        """
        Report from GitHub issue 4360
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4360
        """
        with (get_unit_tests_scans_path("zap") / "dvwa_baseline_dojo.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(19, len(findings))
            self.validate_locations(findings)
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("X-Frame-Options Header Not Set", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("10020", finding.vuln_id_from_tool)
                self.assertEqual(11, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("172.17.0.2", location.host)
                self.assertEqual(80, location.port)
                location = self.get_unsaved_locations(finding)[1]
                self.assertEqual("http", location.protocol)
                self.assertEqual("172.17.0.2", location.host)
                self.assertEqual("vulnerabilities/sqli_blind/", location.path)
            with self.subTest(i=18):
                finding = findings[18]
                self.assertEqual("Private IP Disclosure", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("2", finding.vuln_id_from_tool)
                self.assertEqual(3, len(self.get_unsaved_locations(finding)))

    def test_parse_issue4697(self):
        """
        Report from GitHub issue 4697
        see: https://github.com/DefectDojo/django-DefectDojo/issues/4697
        """
        with (get_unit_tests_scans_path("zap") / "zap-results-first-scan.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(15, len(findings))
            self.validate_locations(findings)

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("User Controllable HTML Element Attribute (Potential XSS)", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("10031", finding.vuln_id_from_tool)
                self.assertEqual(11, len(self.get_unsaved_locations(finding)))

                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("http", location.protocol)
                self.assertEqual("bodgeit.securecodebox-demo.svc", location.host)
                self.assertEqual(8080, location.port)

                location = self.get_unsaved_locations(finding)[1]
                self.assertEqual("http", location.protocol)
                self.assertEqual("bodgeit.securecodebox-demo.svc", location.host)
                self.assertEqual("bodgeit/product.jsp", location.path)
            with self.subTest(i=14):
                finding = findings[14]
                self.assertEqual("PII Disclosure", finding.title)
                self.assertEqual("High", finding.severity)
                self.assertEqual("10062", finding.vuln_id_from_tool)
                self.assertEqual(359, finding.cwe)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("http", location.protocol)
                self.assertEqual("bodgeit.securecodebox-demo.svc", location.host)
                self.assertEqual("bodgeit/contact.jsp", location.path)

    def test_parse_juicy(self):
        """Generated with OWASP Juicy shop"""
        with (get_unit_tests_scans_path("zap") / "juicy2.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(6, len(findings))
            self.validate_locations(findings)

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Incomplete or No Cache-control Header Set", finding.title)
                self.assertEqual("Low", finding.severity)
                self.assertEqual("10015", finding.vuln_id_from_tool)
                self.assertEqual(20, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual("juice-shop.herokuapp.com", location.host)
                self.assertEqual(443, location.port)
                location = self.get_unsaved_locations(finding)[1]
                self.assertEqual("https", location.protocol)
                self.assertEqual("juice-shop.herokuapp.com", location.host)
                self.assertEqual("assets/public/polyfills-es2018.js", location.path)
            with self.subTest(i=5):
                finding = findings[5]
                self.assertEqual("CSP: Wildcard Directive", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("10055", finding.vuln_id_from_tool)
                self.assertEqual(693, finding.cwe)
                self.assertEqual(2, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual("juice-shop.herokuapp.com", location.host)
                self.assertEqual("assets", location.path)

    def test_parse_xml_plus_format(self):
        with (get_unit_tests_scans_path("zap") / "zap-xml-plus-format.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(1, len(findings))
            self.validate_locations(findings)

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Insecure HTTP Method - PUT", finding.title)
                self.assertEqual("Medium", finding.severity)
                self.assertEqual("90028", finding.vuln_id_from_tool)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("http", location.protocol)
                self.assertEqual("localhost", location.host)
                self.assertEqual(8080, location.port)
                # Check request and response pair
                request_pair = finding.unsaved_req_resp[0]
                request = request_pair["req"]
                response = request_pair["resp"]
                self.assertEqual('HTTP/1.1 403 Forbidden\nServer: Apache-Coyote/1.1\nContent-Type: text/html;charset=utf-8\nContent-Language: en\nContent-Length: 1004\nDate: Fri, 30 Sep 2022 06:40:15 GMT\n\n<!DOCTYPE html><html><head><title>Apache Tomcat/8.0.37 - Error report</title><style type="text/css">H1 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:22px;} H2 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:16px;} H3 {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;font-size:14px;} BODY {font-family:Tahoma,Arial,sans-serif;color:black;background-color:white;} B {font-family:Tahoma,Arial,sans-serif;color:white;background-color:#525D76;} P {font-family:Tahoma,Arial,sans-serif;background:white;color:black;font-size:12px;}A {color : black;}A.name {color : black;}.line {height: 1px; background-color: #525D76; border: none;}</style> </head><body><h1>HTTP Status 403 - </h1><div class="line"></div><p><b>type</b> Status report</p><p><b>message</b> <u></u></p><p><b>description</b> <u>Access to the specified resource has been forbidden.</u></p><hr class="line"><h3>Apache Tomcat/8.0.37</h3></body></html>', response)
                self.assertEqual('PUT http://localhost:8080/bodgeit/js/qndto7n63d HTTP/1.1\nHost: localhost:8080\nUser-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:105.0) Gecko/20100101 Firefox/105.0\nAccept: */*\nAccept-Language: de,en-US;q=0.7,en;q=0.3\nConnection: keep-alive\nReferer: https://localhost:8080/bodgeit/\nCookie: JSESSIONID=9E75E26E50F681208096FFAA0B566901\nSec-Fetch-Dest: script\nSec-Fetch-Mode: no-cors\nSec-Fetch-Site: same-origin\nContent-Length: 35\n\n"J0O0glajHdR0Mgp":"UToh9IpCY5zh3CB"', request)

    def test_parse_xml_2_16_1_with_req_resp(self):
        with (get_unit_tests_scans_path("zap") / "zap_2.16.1_with_req_resp.xml").open(encoding="utf-8") as testfile:
            parser = ZapParser()
            findings = parser.get_findings(testfile, Test())
            self.assertIsInstance(findings, list)
            self.assertEqual(4, len(findings))
            self.validate_locations(findings)

            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual("Authentication Request Identified", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("10111", finding.vuln_id_from_tool)
                self.assertEqual(1, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual("example-domain.com", location.host)
                self.assertEqual(443, location.port)
                # Check request and response pair
                self.assertEqual(1, len(finding.unsaved_req_resp))
                request_pair = finding.unsaved_req_resp[0]
                request = request_pair["req"]
                response = request_pair["resp"]
                # I can't make sense of the whitespace diff the assertEqual is producing, so I will just check the stripped versions
                expected_request = """
                            POST https://example-domain.com/cpapi/api/account/verifypasswordless HTTP/1.1
                            host: example-domain.com
                            user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
                            pragma: no-cache
                            cache-control: no-cache
                            accept: */*
                            content-type: application/json-patch+json
                            x-api-version: "[REDACTED]"
                            X-Correlation-Id: "[REDACTED]"
                            content-length: 89
                            authorization: Bearer [REDACTED]

                        {"user_identifier":"string","method":0,"client_id":"string","passwordless_code":"string"}
                            """

                self.assertEqual(expected_request.strip(), request.strip())
                expected_response = """
                            HTTP/1.1 400 Bad Request
                            Cache-Control: no-store, no-cache
                            Content-Length: 0
                            Set-Cookie: TiPMix=[REDACTED]; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: x-ms-routing-name=self; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: HttpOnly=true
                            Set-Cookie: ARRAffinity=[REDACTED];Path=/;HttpOnly;Secure;Domain=example-internal-domain.net
                            Set-Cookie: ARRAffinitySameSite=[REDACTED];Path=/;HttpOnly;SameSite=None;Secure;Domain=example-internal-domain.net
                            Strict-Transport-Security: max-age=31536000; includeSubDomains
                            Request-Context: appId=cid-v1:[REDACTED]
                            X-Frame-Options: SAMEORIGIN
                            Content-Security-Policy: frame-ancestors 'self'
                            X-Content-Type-Options: nosniff
                            X-XSS-Protection: 1; mode=block
                            X-Correlation-Id: [REDACTED]
                            Access-Control-Allow-Origin: *
                            Access-Control-Allow-Headers: *
                            Access-Control-Allow-Methods: *
                            Date: Sun, 22 Jun 2025 00:17:25 GMT
                            """
                self.assertEqual(expected_response.strip(), response.strip())

            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual("Cookie Poisoning", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("10029", finding.vuln_id_from_tool)
                self.assertEqual(5, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual("example-domain.com", location.host)
                self.assertEqual(443, location.port)
                # Check request and response pair
                self.assertEqual(5, len(finding.unsaved_req_resp))
                request_pair = finding.unsaved_req_resp[0]
                request = request_pair["req"]
                response = request_pair["resp"]
                # I can't make sense of the whitespace diff the assertEqual is producing, so I will just check the stripped versions
                expected_request = """
                            GET https://example-domain.com/cpapi/api/redirect/getPrefillOtuTokenData?otuToken=otuToken&clearCache=true HTTP/1.1
                            host: example-domain.com
                            user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
                            pragma: no-cache
                            cache-control: no-cache
                            accept: text/plain, application/json, text/json
                            x-api-version: "[REDACTED]"
                            X-Correlation-Id: "[REDACTED]"
                            content-length: 0
                            authorization: Bearer [REDACTED]
                            """

                self.assertEqual(expected_request.strip(), request.strip())
                expected_response = """
                            HTTP/1.1 400 Bad Request
                            Cache-Control: no-store, no-cache
                            Content-Length: 0
                            Set-Cookie: TiPMix=[REDACTED]; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: x-ms-routing-name=self; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: HttpOnly=true
                            Set-Cookie: ARRAffinity=[REDACTED];Path=/;HttpOnly;Secure;Domain=example-internal-domain.net
                            Set-Cookie: ARRAffinitySameSite=[REDACTED];Path=/;HttpOnly;SameSite=None;Secure;Domain=example-internal-domain.net
                            Strict-Transport-Security: max-age=31536000; includeSubDomains
                            Request-Context: appId=cid-v1:[REDACTED]
                            X-Frame-Options: SAMEORIGIN
                            Content-Security-Policy: frame-ancestors 'self'
                            X-Content-Type-Options: nosniff
                            X-XSS-Protection: 1; mode=block
                            X-Correlation-Id: [REDACTED]
                            Access-Control-Allow-Origin: *
                            Access-Control-Allow-Headers: *
                            Access-Control-Allow-Methods: *
                            Date: Sun, 22 Jun 2025 00:17:24 GMT
                            """
                self.assertEqual(expected_response.strip(), response.strip())

            with self.subTest(i=2):
                finding = findings[2]
                self.assertEqual("Information Disclosure - Sensitive Information in URL", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("10024", finding.vuln_id_from_tool)
                self.assertEqual(3, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual("example-domain.com", location.host)
                self.assertEqual(443, location.port)
                # Check request and response pair
                self.assertEqual(3, len(finding.unsaved_req_resp))
                request_pair = finding.unsaved_req_resp[0]
                request = request_pair["req"]
                response = request_pair["resp"]
                # I can't make sense of the whitespace diff the assertEqual is producing, so I will just check the stripped versions
                expected_request = """
                            GET https://example-domain.com/cpapi/api/oid/validateToken?accessToken=accessToken HTTP/1.1
                            host: example-domain.com
                            user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
                            pragma: no-cache
                            cache-control: no-cache
                            accept: text/plain, application/json, text/json
                            x-api-version: "[REDACTED]"
                            X-Correlation-Id: "[REDACTED]"
                            content-length: 0
                            authorization: Bearer [REDACTED]

                            """

                self.assertEqual(expected_request.strip(), request.strip())
                expected_response = """
                            HTTP/1.1 400 Bad Request
                            Cache-Control: no-store, no-cache
                            Content-Length: 0
                            Set-Cookie: TiPMix=[REDACTED]; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: x-ms-routing-name=self; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: HttpOnly=true
                            Set-Cookie: ARRAffinity=[REDACTED];Path=/;HttpOnly;Secure;Domain=example-internal-domain.net
                            Set-Cookie: ARRAffinitySameSite=[REDACTED];Path=/;HttpOnly;SameSite=None;Secure;Domain=example-internal-domain.net
                            Strict-Transport-Security: max-age=31536000; includeSubDomains
                            Request-Context: appId=cid-v1:[REDACTED]
                            X-Frame-Options: SAMEORIGIN
                            Content-Security-Policy: frame-ancestors 'self'
                            X-Content-Type-Options: nosniff
                            X-XSS-Protection: 1; mode=block
                            X-Correlation-Id: [REDACTED]
                            Access-Control-Allow-Origin: *
                            Access-Control-Allow-Headers: *
                            Access-Control-Allow-Methods: *
                            Date: Sun, 22 Jun 2025 00:17:24 GMT
                            """
                self.assertEqual(expected_response.strip(), response.strip())

            with self.subTest(i=3):
                finding = findings[3]
                self.assertEqual("Re-examine Cache-control Directives", finding.title)
                self.assertEqual("Info", finding.severity)
                self.assertEqual("10015", finding.vuln_id_from_tool)
                self.assertEqual(4, len(self.get_unsaved_locations(finding)))
                location = self.get_unsaved_locations(finding)[0]
                self.assertEqual("https", location.protocol)
                self.assertEqual("example-domain.com", location.host)
                self.assertEqual(443, location.port)
                # Check request and response pair
                self.assertEqual(4, len(finding.unsaved_req_resp))
                request_pair = finding.unsaved_req_resp[0]
                request = request_pair["req"]
                response = request_pair["resp"]
                # I can't make sense of the whitespace diff the assertEqual is producing, so I will just check the stripped versions
                expected_request = """
                            DELETE https://example-domain.com/cpapi/api/workflow/config/json/tenant/product/topic/key?persistence=0 HTTP/1.1
                            host: example-domain.com
                            user-agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
                            pragma: no-cache
                            cache-control: no-cache
                            accept: */*
                            X-Correlation-Id: "[REDACTED]"
                            content-length: 0
                            authorization: Bearer [REDACTED]

                            """

                self.assertEqual(expected_request.strip(), request.strip())
                expected_response = """
                            HTTP/1.1 200 OK
                            Cache-Control: no-store, no-cache
                            Content-Type: application/json
                            Set-Cookie: TiPMix=[REDACTED]; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: x-ms-routing-name=self; path=/; HttpOnly; Domain=example-internal-domain.net; Max-Age=3600; Secure; SameSite=None
                            Set-Cookie: HttpOnly=true
                            Set-Cookie: ARRAffinity=[REDACTED];Path=/;HttpOnly;Secure;Domain=example-internal-domain.net
                            Set-Cookie: ARRAffinitySameSite=[REDACTED];Path=/;HttpOnly;SameSite=None;Secure;Domain=example-internal-domain.net
                            Strict-Transport-Security: max-age=31536000; includeSubDomains
                            Request-Context: appId=cid-v1:[REDACTED]
                            X-Frame-Options: SAMEORIGIN
                            Content-Security-Policy: frame-ancestors 'self'
                            X-Content-Type-Options: nosniff
                            X-XSS-Protection: 1; mode=block
                            X-Correlation-Id: [REDACTED]
                            Access-Control-Allow-Origin: *
                            Access-Control-Allow-Headers: *
                            Access-Control-Allow-Methods: *
                            Date: Sun, 22 Jun 2025 00:17:25 GMT
                            content-length: 1631

                        {"data":[{"item1":"[FEATURE_FLAG_1]","item2":true},{"item1":"[FEATURE_FLAG_2]","item2":true},{"item1":"[FEATURE_FLAG_3]","item2":true},{"item1":"[FEATURE_FLAG_4]","item2":true},{"item1":"[FEATURE_FLAG_5]","item2":true},{"item1":"[FEATURE_FLAG_6]","item2":true},{"item1":"[FEATURE_FLAG_7]","item2":true},{"item1":"[FEATURE_FLAG_8]","item2":true},{"item1":"[FEATURE_FLAG_9]","item2":true},{"item1":"[FEATURE_FLAG_10]","item2":true},{"item1":"[FEATURE_FLAG_11]","item2":true},{"item1":"[FEATURE_FLAG_12]","item2":true},{"item1":"[FEATURE_FLAG_13]","item2":false},{"item1":"[FEATURE_FLAG_14]","item2":false},{"item1":"[FEATURE_FLAG_15]","item2":false},{"item1":"[FEATURE_FLAG_16]","item2":true},{"item1":"[FEATURE_FLAG_17]","item2":true},{"item1":"[FEATURE_FLAG_18]","item2":true},{"item1":"[FEATURE_FLAG_19]","item2":true},{"item1":"[FEATURE_FLAG_20]","item2":true},{"item1":"[FEATURE_FLAG_21]","item2":true},{"item1":"[FEATURE_FLAG_22]","item2":true},{"item1":"[FEATURE_FLAG_23]","item2":false},{"item1":"[FEATURE_FLAG_24]","item2":false},{"item1":"[FEATURE_FLAG_25]","item2":false},{"item1":"[FEATURE_FLAG_26]","item2":true},{"item1":"[FEATURE_FLAG_27]","item2":false},{"item1":"[FEATURE_FLAG_28]","item2":true},{"item1":"[FEATURE_FLAG_29]","item2":true},{"item1":"[FEATURE_FLAG_30]","item2":false},{"item1":"[FEATURE_FLAG_31]","item2":true},{"item1":"[FEATURE_FLAG_32]","item2":true}],"isSuccess":true,"message":"Features retrieved successfully","reason":null,"code":"200","validation":null,"applicationId":null}
                            """
                self.assertEqual(expected_response.strip(), response.strip())
