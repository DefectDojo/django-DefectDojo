from .parser_helper import get_defectdojo_findings
from dojo.models import Finding
import re
import logging

logger = logging.getLogger(__name__)

__author__ = "Vijay Bheemineni"
__license__ = "MIT"
__version__ = "1.0.0"
__status__ = "Development"


class AcunetixScannerParser(object):
    """
        This class parse Acunetix XML file using helper methods from 'parser_helper.py'.
    """

    def __init__(self, xml_output, test):
        self.items = []
        if xml_output is None:
            return
        acunetix_defectdojo_findings = get_defectdojo_findings(xml_output)
        self.set_defectdojo_findings(acunetix_defectdojo_findings, test)

    def set_defectdojo_findings(self, acunetix_defectdojo_findings, test):
        defectdojo_findings = []

        for acunetix_defectdojo_finding in acunetix_defectdojo_findings:

            defectdojo_title = acunetix_defectdojo_finding.title
            defectdojo_date = get_defectdojo_date(acunetix_defectdojo_finding.date)
            defectdojo_cwe_number = get_cwe_number(acunetix_defectdojo_finding.cwe)
            defectdojo_severity = get_severity(acunetix_defectdojo_finding.severity)
            defectdojo_falsep = get_false_positive(acunetix_defectdojo_finding.false_p)

            defectdojo_findings_titles = [finding.title for finding in defectdojo_findings]

            if defectdojo_title not in defectdojo_findings_titles:
                finding = Finding(
                            title=defectdojo_title,
                            date=defectdojo_date,
                            url=acunetix_defectdojo_finding.url,
                            cwe=defectdojo_cwe_number,
                            test=test,
                            severity=defectdojo_severity,
                            description=acunetix_defectdojo_finding.description,
                            mitigation=acunetix_defectdojo_finding.mitigation,
                            references=acunetix_defectdojo_finding.references,
                            impact=acunetix_defectdojo_finding.impact,
                            false_p=defectdojo_falsep,
                            dynamic_finding=acunetix_defectdojo_finding.dynamic_finding
                )
                defectdojo_findings.append(finding)
            else:
                logger.debug(("Duplicate finding : {defectdojo_title}".format(defectdojo_title=defectdojo_title)))

        self.items = defectdojo_findings


def get_defectdojo_date(date):
    """
        Returns date as required by DefectDojo.
    :param date:
    :return: yyyy--mm-dd
    """
    regex = r"([0-9]{2})\/([0-9]{2})\/([0-9]{4})"
    matches = re.finditer(regex, date, re.MULTILINE)
    match = next(enumerate(matches))
    date = match[1].groups()
    day = date[0]
    mon = date[1]
    year = date[2]
    defectdojo_date = "{year}-{mon}-{day}".format(year=year, mon=mon, day=day)
    # print(defectdojo_date)
    return defectdojo_date


def get_cwe_number(cwe):
    """
        Returns cwe number.
    :param cwe:
    :return: cwe number
    """
    if cwe is None:
        return None
    else:
        return cwe.split("-")[1]


def get_severity(severity):
    """
        Returns Severity as per DefectDojo standards.
    :param severity:
    :return:
    """
    if severity == "high":
        return "High"
    elif severity == "medium":
        return "Medium"
    elif severity == "low":
        return "Low"
    elif severity == "informational":
        return "Informational"
    else:
        return "Critical"


def get_false_positive(false_p):
    """
        Returns True, False for false positive as per DefectDojo standards.
    :param false_p:
    :return:
    """
    if false_p:
        return True
    else:
        return False
