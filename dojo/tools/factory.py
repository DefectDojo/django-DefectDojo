from dojo.tools.burp.parser import BurpXmlParser
from dojo.tools.nessus.parser import NessusCSVParser, NessusXMLParser
from dojo.tools.nexpose.parser import NexposeFullXmlParser
from dojo.tools.veracode.parser import VeracodeXMLParser
from dojo.tools.zap.parser import ZapXmlParser
from dojo.tools.checkmarx.parser import CheckmarxXMLParser
from dojo.tools.appspider.parser import AppSpiderXMLParser
from dojo.tools.arachni.parser import ArachniJSONParser

__author__ = 'Jay Paz'


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
    else:
        raise ValueError('Unknown Test Type')

    return parser
