from dojo.tools.burp.parser import BurpXmlParser
from dojo.tools.nessus.parser import NessusCSVParser, NessusXMLParser
from dojo.tools.nmap.parser import NmapXMLParser
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.tools.veracode.parser import VeracodeXMLParser
from dojo.tools.zap.parser import ZapXmlParser
from dojo.tools.checkmarx.parser import CheckmarxXMLParser
from dojo.tools.crashtest_security.parser import CrashtestSecurityXmlParser
from dojo.tools.contrast.parser import ContrastCSVParser
from dojo.tools.bandit.parser import BanditParser
from dojo.tools.appspider.parser import AppSpiderXMLParser
from dojo.tools.arachni.parser import ArachniJSONParser
from dojo.tools.vcg.parser import VCGParser
from dojo.tools.dependencycheck.parser import DependencyCheckParser
from dojo.tools.retirejs.parser import RetireJsParser
from dojo.tools.nsp.parser import NspParser
from dojo.tools.npmaudit.parser import NpmAuditParser
from dojo.tools.generic.parser import GenericFindingUploadCsvParser
from dojo.tools.qualys.parser import QualysParser
from dojo.tools.qualyswebapp.parser import QualysWebAppParser
from dojo.tools.snyk.parser import SnykParser
from dojo.tools.gosec.parser import GosecScannerParser
from dojo.tools.openvas_csv.parser import OpenVASUploadCsvParser
from dojo.tools.trustwave_csv.parser import TrustwaveUploadCsvParser
from dojo.tools.skf.parser import SKFCsvParser
from dojo.tools.ssllabs.parser import SSLlabsParser
from dojo.tools.nikto.parser import NiktoXMLParser
from dojo.tools.trufflehog.parser import TruffleHogJSONParser
from dojo.tools.php_security_audit_v2.parser import PhpSecurityAuditV2
from dojo.tools.acunetix.parser import AcunetixScannerParser
from dojo.tools.fortify.parser import FortifyXMLParser
from dojo.tools.sonarqube.parser import SonarQubeHtmlParser
from dojo.tools.clair.parser import ClairParser
from dojo.tools.mobsf.parser import MobSFParser
from dojo.tools.awsscout2.parser import AWSScout2Parser
from dojo.tools.awsprowler.parser import AWSProwlerParser
from dojo.tools.brakeman.parser import BrakemanScanParser
from dojo.tools.spotbugs.parser import SpotbugsXMLParser

__author__ = 'Jay Paz'


def import_parser_factory(file, test, scan_type=None):
    scan_type = test.test_type.name
    if scan_type == "Burp Scan":
        parser = BurpXmlParser(file, test)
    elif scan_type == "Nessus Scan":
        filename = file.name.lower()
        if filename.endswith("csv"):
            parser = NessusCSVParser(file, test)
        elif filename.endswith("xml") or filename.endswith("nessus"):
            parser = NessusXMLParser(file, test)
    elif scan_type == "Clair Scan":
        parser = ClairParser(file, test)
    elif scan_type == "Nmap Scan":
        parser = NmapXMLParser(file, test)
    elif scan_type == "Nikto Scan":
        parser = NiktoXMLParser(file, test)
    elif scan_type == "Nexpose Scan":
        parser = NexposeFullXmlParser(file, test)
    elif scan_type == "Veracode Scan":
        parser = VeracodeXMLParser(file, test)
    elif scan_type == "Checkmarx Scan":
        parser = CheckmarxXMLParser(file, test)
    elif scan_type == "Contrast Scan":
        parser = ContrastCSVParser(file, test)
    elif scan_type == "Crashtest Security Scan":
        parser = CrashtestSecurityXmlParser(file, test)
    elif scan_type == "Bandit Scan":
        parser = BanditParser(file, test)
    elif scan_type == "ZAP Scan":
        parser = ZapXmlParser(file, test)
    elif scan_type == "AppSpider Scan":
        parser = AppSpiderXMLParser(file, test)
    elif scan_type == "Arachni Scan":
        parser = ArachniJSONParser(file, test)
    elif scan_type == 'VCG Scan':
        parser = VCGParser(file, test)
    elif scan_type == 'Dependency Check Scan':
        parser = DependencyCheckParser(file, test)
    elif scan_type == 'Retire.js Scan':
        parser = RetireJsParser(file, test)
    elif scan_type == 'Node Security Platform Scan':
        parser = NspParser(file, test)
    elif scan_type == 'NPM Audit Scan':
        parser = NpmAuditParser(file, test)
    elif scan_type == 'Generic Findings Import':
        parser = GenericFindingUploadCsvParser(file, test)
    elif scan_type == 'Qualys Scan':
        parser = QualysParser(file, test)
    elif scan_type == 'Qualys Webapp Scan':
        parser = QualysWebAppParser(file, test)
    elif scan_type == "OpenVAS CSV":
        parser = OpenVASUploadCsvParser(file, test)
    elif scan_type == 'Snyk Scan':
        parser = SnykParser(file, test)
    elif scan_type == 'SKF Scan':
        parser = SKFCsvParser(file, test)
    elif scan_type == 'SSL Labs Scan':
        parser = SSLlabsParser(file, test)
    elif scan_type == 'Trufflehog Scan':
        parser = TruffleHogJSONParser(file, test)
    elif scan_type == 'Gosec Scanner':
        parser = GosecScannerParser(file, test)
    elif scan_type == 'Trustwave Scan (CSV)':
        parser = TrustwaveUploadCsvParser(file, test)
    elif scan_type == 'PHP Security Audit v2':
        parser = PhpSecurityAuditV2(file, test)
    elif scan_type == 'Acunetix Scan':
        parser = AcunetixScannerParser(file, test)
    elif scan_type == 'Fortify Scan':
        parser = FortifyXMLParser(file, test)
    elif scan_type == 'SonarQube Scan':
        parser = SonarQubeHtmlParser(file, test)
    elif scan_type == 'MobSF Scan':
        parser = MobSFParser(file, test)
    elif scan_type == 'AWS Scout2 Scan':
        parser = AWSScout2Parser(file, test)
    elif scan_type == 'AWS Prowler Scan':
        parser = AWSProwlerParser(file, test)
    elif scan_type == 'Brakeman Scan':
        parser = BrakemanScanParser(file, test)
    elif scan_type == 'SpotBugs Scan':
        parser = SpotbugsXMLParser(file, test)
    else:
        raise ValueError('Unknown Test Type')

    return parser
