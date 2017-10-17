from dojo.tools.burp.parser import BurpXmlParser
from dojo.tools.nessus.parser import NessusCSVParser, NessusXMLParser
from dojo.tools.nmap.parser import NmapXMLParser
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.tools.veracode.parser import VeracodeXMLParser
from dojo.tools.zap.parser import ZapXmlParser
from dojo.tools.checkmarx.parser import CheckmarxXMLParser
from dojo.tools.appspider.parser import AppSpiderXMLParser
from dojo.tools.arachni.parser import ArachniJSONParser
from dojo.tools.vcg.parser import VCGParser
from dojo.tools.dependencycheck.parser import DependencyCheckParser
from dojo.tools.retirejs.parser import RetireJsParser
from dojo.tools.nsp.parser import NspParser
from dojo.tools.generic.parser import GenericFindingUploadCsvParser
from dojo.tools.qualys.parser import QualysParser
from dojo.tools.qualyswebapp.parser import QualysWebAppParser
from dojo.tools.openvas_csv.parser import OpenVASUploadCsvParser


__author__ = 'Jay Paz'

#Modified by dkade to use OpenVASUploadCsvParser

def import_parser_factory(file, test):
    scan_type = test.test_type.name
    if scan_type == "Burp Scan":
        parser = BurpXmlParser(file, test)
    elif scan_type == "Nessus Scan":
        filename = file.name.lower()
        if filename.endswith("csv"):
            parser = NessusCSVParser(file, test)
        elif filename.endswith("xml") or filename.endswith("nessus"):
            parser = NessusXMLParser(file, test)
    elif scan_type == "Nmap Scan":
        parser = NmapXMLParser(file, test)
    elif scan_type == "Nexpose Scan":
        parser = NexposeFullXmlParser(file, test)
    elif scan_type == "Veracode Scan":
        parser = VeracodeXMLParser(file, test)
    elif scan_type == "Checkmarx Scan":
        parser = CheckmarxXMLParser(file, test)
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
    elif scan_type == 'Generic Findings Import':
        parser = GenericFindingUploadCsvParser(file, test)
    elif scan_type == 'Qualys Scan':
        parser = QualysParser(file, test)
    elif scan_type == 'Qualys Webapp Scan':
        parser = QualysWebAppParser(file, test)
    elif scan_type == "OpenVAS CSV":
        parser = OpenVASUploadCsvParser(file, test)
    else:
        raise ValueError('Unknown Test Type')

    return parser
