import datetime
from unittest.mock import MagicMock, patch

from dojo.models import Test
from dojo.tools.risk_recon.api import RiskReconAPI
from dojo.tools.risk_recon.parser import RiskReconParser
from dojo.utils_ssrf import SSRFError
from unittests.dojo_test_case import DojoTestCase, get_unit_tests_scans_path


class TestRiskReconAPIParser(DojoTestCase):

    def test_api_with_bad_url(self):
        with (get_unit_tests_scans_path("risk_recon") / "bad_url.json").open(encoding="utf-8") as testfile, \
          self.assertRaises(Exception):  # noqa: B017  # SSRFError is caught and re-raised as Exception in api.py
            parser = RiskReconParser()
            parser.get_findings(testfile, Test())

    def test_api_with_bad_key(self):
        with (get_unit_tests_scans_path("risk_recon") / "bad_key.json").open(encoding="utf-8") as testfile, \
          self.assertRaises(Exception):  # noqa: B017 #TODO: Exception from tools/risk_recon/api.py --> def map_toes(self)
            parser = RiskReconParser()
            parser.get_findings(testfile, Test())

    def test_parser_without_api(self):
        with (get_unit_tests_scans_path("risk_recon") / "findings.json").open(encoding="utf-8") as testfile:
            parser = RiskReconParser()
            findings = parser.get_findings(testfile, Test())
            self.assertEqual(2, len(findings))
            with self.subTest(i=0):
                finding = findings[0]
                self.assertEqual(datetime.date(2017, 3, 17), finding.date.date())
                self.assertEqual("ff2bbdbfc2b6fddc061ed96b1fasfwefb", finding.unique_id_from_tool)
            with self.subTest(i=1):
                finding = findings[1]
                self.assertEqual(datetime.date(2017, 3, 17), finding.date.date())
                self.assertEqual("ff2bbdbfc2b6gsrgwergwe6b1fasfwefb", finding.unique_id_from_tool)

    @patch("dojo.tools.risk_recon.api.validate_url_for_ssrf", side_effect=SSRFError("blocked: private address"))
    def test_ssrf_error_is_raised_as_exception(self, mock_validate):
        with self.assertRaisesRegex(Exception, "Invalid Risk Recon API url"):
            RiskReconAPI(api_key="somekey", endpoint="http://192.168.1.1/api", data=[])
        mock_validate.assert_called_once_with("http://192.168.1.1/api")

    @patch.object(RiskReconAPI, "get_findings")
    @patch.object(RiskReconAPI, "map_toes")
    @patch("dojo.tools.risk_recon.api.make_ssrf_safe_session")
    @patch("dojo.tools.risk_recon.api.validate_url_for_ssrf")
    def test_make_ssrf_safe_session_called_on_init(self, mock_validate, mock_make_session, mock_map_toes, mock_get_findings):
        mock_session = MagicMock()
        mock_make_session.return_value = mock_session
        api = RiskReconAPI(api_key="somekey", endpoint="https://api.riskrecon.com/v1", data=[])
        mock_make_session.assert_called_once()
        self.assertIs(api.session, mock_session)
