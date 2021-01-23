import logging
from dojo.models import Test_Type

PARSERS = {}
# TODO remove that
SCAN_SONARQUBE_API = 'SonarQube API Import'


def register_parser(scan_type, parser):
    logging.info(f"register scan_type:{scan_type}")
    # check double registration or registration with an existing key
    if scan_type in PARSERS:
        raise ValueError(f'Try to register an existing parser {scan_type}')
    # create dynamicaly in DB
    test_type, created = Test_Type.objects.get_or_create(name=scan_type)
    if created:
        test_type.save()
    PARSERS[scan_type] = parser


def import_parser_factory(file, test, active, verified, scan_type=None):
    """Return a parser by the scan type
    This fucntion exists only for backward compatibility
    """
    if scan_type in PARSERS:
        return PARSERS[scan_type]
    else:
        raise ValueError(f'Unknown Test Type {scan_type}')


def get_choices():
    res = list()
    res.append(("", "Please Select a Scan Type"))
    for key in PARSERS:
        res.append((key, key))
    return res


def requires_file(scan_type):
    if scan_type is None or scan_type not in PARSERS:
        return False
    # FIXME switch to method of the parser
    # parser = PARSERS[scan_type]
    return scan_type != SCAN_SONARQUBE_API


def handles_active_verified_statuses(scan_type):
    # FIXME switch to method of the parser
    # parser = PARSERS[scan_type]
    return scan_type in [
        'Generic Findings Import', SCAN_SONARQUBE_API, 'Qualys Scan'
    ]


from .acunetix.parser import AcunetixScannerParser
register_parser('Acunetix Scan', AcunetixScannerParser())
from .anchore_engine.parser import AnchoreEngineScanParser
register_parser('Anchore Engine Scan', AnchoreEngineScanParser())
from .anchore_enterprise.parser import AnchoreEnterprisePolicyCheckParser
register_parser('Anchore Enterprise Policy Check', AnchoreEnterprisePolicyCheckParser())
from .appspider.parser import AppSpiderXMLParser
register_parser('AppSpider Scan', AppSpiderXMLParser())
from .aqua.parser import AquaJSONParser
register_parser('Aqua Scan', AquaJSONParser())
from .arachni.parser import ArachniJSONParser
register_parser('Arachni Scan', ArachniJSONParser())
from .aws_prowler.parser import AWSProwlerParser
register_parser('AWS Prowler Scan', AWSProwlerParser())
from .aws_scout2.parser import AWSScout2Parser
register_parser('AWS Scout2 Scan', AWSScout2Parser())
from .awssecurityhub.parser import AwsSecurityFindingFormatParser
register_parser('AWS Security Hub Scan', AwsSecurityFindingFormatParser())
from .bandit.parser import BanditParser
register_parser('Bandit Scan', BanditParser())
from .blackduck_component_risk.parser import BlackduckCRImporter
register_parser('Blackduck Component Risk', BlackduckCRImporter())
from .blackduck.parser import BlackduckHubCSVParser
register_parser('Blackduck Hub Scan', BlackduckHubCSVParser())
from .brakeman.parser import BrakemanScanParser
register_parser('Brakeman Scan', BrakemanScanParser())
from .bugcrowd.parser import BugCrowdCSVParser
register_parser('BugCrowd Scan', BugCrowdCSVParser())
from .bundler_audit.parser import BundlerAuditParser
register_parser('Bundler-Audit Scan', BundlerAuditParser())
from .burp_enterprise.parser import BurpEnterpriseHtmlParser
register_parser('Burp Enterprise Scan', BurpEnterpriseHtmlParser())
from .burp_api.parser import BurpApiParser
register_parser('Burp REST API', BurpApiParser())
from .burp.parser import BurpXmlParser
register_parser('Burp Scan', BurpXmlParser())
# register_parser('CCVS Report', Parser())
# register_parser('Checkmarx Scan', Parser())
# register_parser('Checkmarx Scan detailed', Parser())
# register_parser('Checkov Scan', Parser())
# register_parser('Choctaw Hog Scan', Parser())
# register_parser('Clair Klar Scan', Parser())
# register_parser('Clair Scan', Parser())
# register_parser('Cobalt.io Scan', Parser())
# register_parser('Contrast Scan', Parser())
# register_parser('Crashtest Security JSON File', Parser())
# register_parser('Crashtest Security XML File', Parser())
# register_parser('DawnScanner Scan', Parser())
# register_parser('Dependency Check Scan', Parser())
# register_parser('Dependency Track Finding Packaging Format (FPF) Export', Parser())
# register_parser('DrHeader JSON Importer', Parser())
from .dsop.parser import DsopParser
register_parser('DSOP Scan', DsopParser())
from .eslint.parser import ESLintParser
register_parser('ESLint Scan', ESLintParser())
# register_parser('Fortify Scan', Parser())
# register_parser('Generic Findings Import', Parser())
# register_parser('Github Vulnerability Scan', Parser())
# register_parser('GitLab Dependency Scanning Report', Parser())
# register_parser('GitLab SAST Report', Parser())
# register_parser('Gitleaks Scan', Parser())
# register_parser('Gosec Scanner', Parser())
# register_parser('HackerOne Cases', Parser())
# register_parser('Hadolint Dockerfile check', Parser())
# register_parser('Harbor Vulnerability Scan', Parser())
# register_parser('HuskyCI Report', Parser())
# register_parser('IBM AppScan DAST', Parser())
# register_parser('Immuniweb Scan', Parser())
# register_parser('JFrog Xray Scan', Parser())
# register_parser('Kiuwan Scan', Parser())
# register_parser('kube-bench Scan', Parser())
# register_parser('Microfocus Webinspect Scan', Parser())
# register_parser('MobSF Scan', Parser())
# register_parser('Mozilla Observatory Scan', Parser())
# register_parser('Nessus Scan', Parser())
# register_parser('Netsparker Scan', Parser())
# register_parser('Nexpose Scan', Parser())
# register_parser('Nikto Scan', Parser())
# register_parser('Nmap Scan', Parser())
# register_parser('Node Security Platform Scan', Parser())
# register_parser('NPM Audit Scan', Parser())
# register_parser('Openscap Vulnerability Scan', Parser())
from .openvas_csv.parser import OpenVASUploadCsvParser
register_parser('OpenVAS CSV', OpenVASUploadCsvParser())
# register_parser('ORT evaluated model Importer', Parser())
# register_parser('OssIndex Devaudit SCA Scan Importer', Parser())
# register_parser('Outpost24 Scan', Parser())
# register_parser('PHP Security Audit v2', Parser())
# register_parser('PHP Symfony Security Check', Parser())
# register_parser('Qualys Infrastructure Scan (WebGUI XML)', Parser())
# register_parser('Qualys Scan', Parser())
# register_parser('Qualys Webapp Scan', Parser())
# register_parser('Retire.js Scan', Parser())
# register_parser('Risk Recon API Importer', Parser())
# register_parser('Safety Scan', Parser())
# register_parser('SARIF', Parser())
# register_parser('Scantist Scan', Parser())
# register_parser('Scout Suite Scan', Parser())
# register_parser('Semgrep JSON Report', Parser())
# register_parser('SKF Scan', Parser())
# register_parser('Snyk Scan', Parser())
# register_parser('SonarQube API Import', Parser())
# register_parser('SonarQube Scan', Parser())
# register_parser('SonarQube Scan detailed', Parser())
# register_parser('Sonatype Application Scan', Parser())
# register_parser('SpotBugs Scan', Parser())
# register_parser('SSL Labs Scan', Parser())
# register_parser('Sslscan', Parser())
# register_parser('SSLyze 3 Scan (JSON)', Parser())
# register_parser('Sslyze Scan', Parser())
# register_parser('Testssl Scan', Parser())
# register_parser('Trivy Scan', Parser())
# register_parser('Trufflehog Scan', Parser())
# register_parser('Trustwave Scan (CSV)', Parser())
# register_parser('Twistlock Image Scan', Parser())
# register_parser('VCG Scan', Parser())
# register_parser('Veracode Scan', Parser())
# register_parser('Wapiti Scan', Parser())
from .whitesource.parser import WhitesourceJSONParser
register_parser('Whitesource Scan', WhitesourceJSONParser())
from .wpscan.parser import WpscanJSONParser
register_parser('Wpscan', WpscanJSONParser())
from .xanitizer.parser import XanitizerXMLParser
register_parser('Xanitizer Scan', XanitizerXMLParser())
from .yarn_audit.parser import YarnAuditParser
register_parser('Yarn Audit Scan', YarnAuditParser())
from .zap.parser import ZapXmlParser
register_parser('ZAP Scan', ZapXmlParser())
