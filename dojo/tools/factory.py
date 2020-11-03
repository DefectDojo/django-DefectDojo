from dojo.tools.burp.parser import BurpXmlParser
from dojo.tools.dsop.parser import DsopParser
from dojo.tools.nessus.parser import NessusCSVParser, NessusXMLParser
from dojo.tools.nmap.parser import NmapXMLParser
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.tools.veracode.parser import VeracodeXMLParser
from dojo.tools.zap.parser import ZapXmlParser
from dojo.tools.checkmarx.parser import CheckmarxXMLParser
from dojo.tools.crashtest_security_xml.parser import CrashtestSecurityXmlParser
from dojo.tools.crashtest_security_json.parser import CrashtestSecurityJsonParser
from dojo.tools.contrast.parser import ContrastCSVParser
from dojo.tools.bandit.parser import BanditParser
from dojo.tools.eslint.parser import ESLintParser
from dojo.tools.appspider.parser import AppSpiderXMLParser
from dojo.tools.arachni.parser import ArachniJSONParser
from dojo.tools.vcg.parser import VCGParser
from dojo.tools.dependency_check.parser import DependencyCheckParser
from dojo.tools.dependency_track.parser import DependencyTrackParser
from dojo.tools.retirejs.parser import RetireJsParser
from dojo.tools.nsp.parser import NspParser
from dojo.tools.npm_audit.parser import NpmAuditParser
from dojo.tools.php_symfony_security_check.parser import PhpSymfonySecurityCheckParser
from dojo.tools.generic.parser import GenericFindingUploadCsvParser
from dojo.tools.qualys.parser import QualysParser
from dojo.tools.qualys_infrascan_webgui.parser import QualysInfraScanParser
from dojo.tools.qualys_webapp.parser import QualysWebAppParser
from dojo.tools.snyk.parser import SnykParser
from dojo.tools.gosec.parser import GosecScannerParser
from dojo.tools.openvas_csv.parser import OpenVASUploadCsvParser
from dojo.tools.trustwave.parser import TrustwaveUploadCsvParser
from dojo.tools.skf.parser import SKFCsvParser
from dojo.tools.ssl_labs.parser import SSLlabsParser
from dojo.tools.nikto.parser import NiktoXMLParser
from dojo.tools.trufflehog.parser import TruffleHogJSONParser
from dojo.tools.netsparker.parser import NetsparkerParser
from dojo.tools.php_security_audit_v2.parser import PhpSecurityAuditV2
from dojo.tools.acunetix.parser import AcunetixScannerParser
from dojo.tools.fortify.parser import FortifyXMLParser
from dojo.tools.sonarqube.parser import SonarQubeHtmlParser
from dojo.tools.sonarqube_api.importer import SonarQubeApiImporter
from dojo.tools.clair.parser import ClairParser
from dojo.tools.mobsf.parser import MobSFParser
from dojo.tools.aws_scout2.parser import AWSScout2Parser
from dojo.tools.aws_prowler.parser import AWSProwlerParser
from dojo.tools.brakeman.parser import BrakemanScanParser
from dojo.tools.spotbugs.parser import SpotbugsXMLParser
from dojo.tools.ibm_app.parser import IbmAppScanDASTXMLParser
from dojo.tools.safety.parser import SafetyParser
from dojo.tools.clair_klar.parser import ClairKlarParser
from dojo.tools.dawnscanner.parser import DawnScannerParser
from dojo.tools.anchore_engine.parser import AnchoreEngineScanParser
from dojo.tools.bundler_audit.parser import BundlerAuditParser
from dojo.tools.twistlock.parser import TwistlockParser
from dojo.tools.kiuwan.parser import KiuwanCSVParser
from dojo.tools.blackduck.parser import BlackduckHubCSVParser
from dojo.tools.sonatype.parser import SonatypeJSONParser
from dojo.tools.openscap.parser import OpenscapXMLParser
from dojo.tools.immuniweb.parser import ImmuniwebXMLParser
from dojo.tools.wapiti.parser import WapitiXMLParser
from dojo.tools.cobalt.parser import CobaltCSVParser
from dojo.tools.mozilla_observatory.parser import MozillaObservatoryJSONParser
from dojo.tools.whitesource.parser import WhitesourceJSONParser
from dojo.tools.microfocus_webinspect.parser import MicrofocusWebinspectXMLParser
from dojo.tools.wpscan.parser import WpscanJSONParser
from dojo.tools.sslscan.parser import SslscanXMLParser
from dojo.tools.jfrogxray.parser import XrayJSONParser
from dojo.tools.sslyze.parser_json import SSLyzeJSONParser
from dojo.tools.sslyze.parser_xml import SSLyzeXMLParser
from dojo.tools.testssl.parser import TestsslCSVParser
from dojo.tools.hadolint.parser import HadolintParser
from dojo.tools import SCAN_SONARQUBE_API
from dojo.tools.aqua.parser import AquaJSONParser
from dojo.tools.blackduck_component_risk.parser import BlackduckHubParser
from dojo.tools.h1.parser import HackerOneJSONParser
from dojo.tools.xanitizer.parser import XanitizerXMLParser
from dojo.tools.trivy.parser import TrivyParser
from dojo.tools.outpost24.parser import Outpost24Parser
from dojo.tools.burp_enterprise.parser import BurpEnterpriseHtmlParser
from dojo.tools.anchore_enterprise.parser import AnchoreEnterprisePolicyCheckParser
from dojo.tools.gitleaks.parser import GitleaksJSONParser
from dojo.tools.harbor_vulnerability.parser import HarborVulnerabilityParser
from dojo.tools.github_vulnerability.parser import GithubVulnerabilityParser
from dojo.tools.choctaw_hog.parser import ChoctawhogParser
from dojo.tools.gitlab_sast.parser import GitlabSastReportParser
from dojo.tools.yarn_audit.parser import YarnAuditParser
from dojo.tools.bugcrowd.parser import BugCrowdCSVParser
from dojo.tools.huskyci.parser import HuskyCIReportParser
from dojo.tools.ccvs.parser import CCVSReportParser
from dojo.tools.awssecurityhub.parser import AwsSecurityFindingFormatParser
from dojo.tools.risk_recon.parser import RiskReconParser
from dojo.tools.drheader.parser import DrHeaderJSONParser
from dojo.tools.checkov.parser import CheckovParser
from dojo.tools.kubebench.parser import KubeBenchParser

__author__ = 'Jay Paz'


# TODO change conditional search of the parser to the mapping
def import_parser_factory(file, test, active, verified, scan_type=None):
    if scan_type is None:
        scan_type = test.test_type.name
    if scan_type == "Burp Scan":
        parser = BurpXmlParser(file, test)
    elif scan_type == "Burp Enterprise Scan":
        parser = BurpEnterpriseHtmlParser(file, test)
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
    elif scan_type == "Checkmarx Scan detailed":
        parser = CheckmarxXMLParser(file, test, 'detailed')
    elif scan_type == "Contrast Scan":
        parser = ContrastCSVParser(file, test)
    elif scan_type == "Crashtest Security JSON File":
        parser = CrashtestSecurityJsonParser(file, test)
    elif scan_type == "Crashtest Security XML File":
        parser = CrashtestSecurityXmlParser(file, test)
    elif scan_type == "Bandit Scan":
        parser = BanditParser(file, test)
    elif scan_type == "ESLint Scan":
        parser = ESLintParser(file, test)
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
    elif scan_type == 'Dependency Track Finding Packaging Format (FPF) Export':
        parser = DependencyTrackParser(file, test)
    elif scan_type == 'Retire.js Scan':
        parser = RetireJsParser(file, test)
    elif scan_type == 'Node Security Platform Scan':
        parser = NspParser(file, test)
    elif scan_type == 'NPM Audit Scan':
        parser = NpmAuditParser(file, test)
    elif scan_type == 'PHP Symfony Security Check':
        parser = PhpSymfonySecurityCheckParser(file, test)
    elif scan_type == 'Generic Findings Import':
        parser = GenericFindingUploadCsvParser(file, test, active, verified)
    elif scan_type == 'Qualys Scan':
        parser = QualysParser(file, test)
    elif scan_type == 'Qualys Infrastructure Scan (WebGUI XML)':
        parser = QualysInfraScanParser(file, test)
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
    elif scan_type == 'Clair Klar Scan':
        parser = ClairKlarParser(file, test)
    elif scan_type == 'Gosec Scanner':
        parser = GosecScannerParser(file, test)
    elif scan_type == 'Trustwave Scan (CSV)':
        parser = TrustwaveUploadCsvParser(file, test)
    elif scan_type == 'Netsparker Scan':
        parser = NetsparkerParser(file, test)
    elif scan_type == 'PHP Security Audit v2':
        parser = PhpSecurityAuditV2(file, test)
    elif scan_type == 'Acunetix Scan':
        parser = AcunetixScannerParser(file, test)
    elif scan_type == 'Fortify Scan':
        parser = FortifyXMLParser(file, test)
    elif scan_type == 'SonarQube Scan':
        parser = SonarQubeHtmlParser(file, test)
    elif scan_type == 'SonarQube Scan detailed':
        parser = SonarQubeHtmlParser(file, test, 'detailed')
    elif scan_type == SCAN_SONARQUBE_API:
        parser = SonarQubeApiImporter(test)
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
    elif scan_type == 'Safety Scan':
        parser = SafetyParser(file, test)
    elif scan_type == 'DawnScanner Scan':
        parser = DawnScannerParser(file, test)
    elif scan_type == 'Anchore Engine Scan':
        parser = AnchoreEngineScanParser(file, test)
    elif scan_type == 'Bundler-Audit Scan':
        parser = BundlerAuditParser(file, test)
    elif scan_type == 'Twistlock Image Scan':
        parser = TwistlockParser(file, test)
    elif scan_type == 'IBM AppScan DAST':
        parser = IbmAppScanDASTXMLParser(file, test)
    elif scan_type == 'Kiuwan Scan':
        parser = KiuwanCSVParser(file, test)
    elif scan_type == 'Blackduck Hub Scan':
        parser = BlackduckHubCSVParser(file, test)
    elif scan_type == 'Blackduck Component Risk':
        parser = BlackduckHubParser(file, test)
    elif scan_type == 'Sonatype Application Scan':
        parser = SonatypeJSONParser(file, test)
    elif scan_type == 'Openscap Vulnerability Scan':
        parser = OpenscapXMLParser(file, test)
    elif scan_type == 'Immuniweb Scan':
        parser = ImmuniwebXMLParser(file, test)
    elif scan_type == 'Wapiti Scan':
        parser = WapitiXMLParser(file, test)
    elif scan_type == 'Cobalt.io Scan':
        parser = CobaltCSVParser(file, test)
    elif scan_type == 'Mozilla Observatory Scan':
        parser = MozillaObservatoryJSONParser(file, test)
    elif scan_type == 'Whitesource Scan':
        parser = WhitesourceJSONParser(file, test)
    elif scan_type == 'Microfocus Webinspect Scan':
        parser = MicrofocusWebinspectXMLParser(file, test)
    elif scan_type == 'Wpscan':
        parser = WpscanJSONParser(file, test)
    elif scan_type == 'Sslscan':
        parser = SslscanXMLParser(file, test)
    elif scan_type == 'JFrog Xray Scan':
        parser = XrayJSONParser(file, test)
    elif scan_type == 'Sslyze Scan':
        parser = SSLyzeXMLParser(file, test)
    elif scan_type == 'SSLyze 3 Scan (JSON)':
        parser = SSLyzeJSONParser(file, test)
    elif scan_type == 'Testssl Scan':
        parser = TestsslCSVParser(file, test)
    elif scan_type == 'Hadolint Dockerfile check':
        parser = HadolintParser(file, test)
    elif scan_type == 'Aqua Scan':
        parser = AquaJSONParser(file, test)
    elif scan_type == 'HackerOne Cases':
        parser = HackerOneJSONParser(file, test)
    elif scan_type == 'Xanitizer Scan':
        parser = XanitizerXMLParser(file, test)
    elif scan_type == 'Trivy Scan':
        parser = TrivyParser(file, test)
    elif scan_type == 'Outpost24 Scan':
        parser = Outpost24Parser(file, test)
    elif scan_type == 'DSOP Scan':
        parser = DsopParser(file, test)
    elif scan_type == 'Anchore Enterprise Policy Check':
        parser = AnchoreEnterprisePolicyCheckParser(file, test)
    elif scan_type == 'Gitleaks Scan':
        parser = GitleaksJSONParser(file, test)
    elif scan_type == 'Harbor Vulnerability Scan':
        parser = HarborVulnerabilityParser(file, test)
    elif scan_type == 'Github Vulnerability Scan':
        parser = GithubVulnerabilityParser(file, test)
    elif scan_type == 'Choctaw Hog Scan':
        parser = ChoctawhogParser(file, test)
    elif scan_type == 'GitLab SAST Report':
        parser = GitlabSastReportParser(file, test)
    elif scan_type == 'Yarn Audit Scan':
        parser = YarnAuditParser(file, test)
    elif scan_type == 'BugCrowd Scan':
        parser = BugCrowdCSVParser(file, test)
    elif scan_type == 'HuskyCI Report':
        parser = HuskyCIReportParser(file, test)
    elif scan_type == 'CCVS Report':
        parser = CCVSReportParser(file, test)
    elif scan_type == 'AWS Security Hub Scan':
        parser = AwsSecurityFindingFormatParser(file, test)
    elif scan_type == 'Risk Recon API Importer':
        parser = RiskReconParser(file, test)
    elif scan_type == 'DrHeader JSON Importer':
        parser = DrHeaderJSONParser(file, test)
    elif scan_type == 'Checkov Scan':
        parser = CheckovParser(file, test)
    elif scan_type == 'kube-bench Scan':
        parser = KubeBenchParser(file, test)
    else:
        raise ValueError('Unknown Test Type')

    return parser
