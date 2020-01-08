from defusedxml import ElementTree
from dojo.models import Finding


class Outpost24Parser:
    def __init__(self, file, test):
        tree = ElementTree.parse(file)
        # TODO: extract ./hostlist/host entries for endpoints
        findings = list()
        for detail in tree.iterfind('//detaillist/detail'):
            title = detail.findtext('name')
            #date = detail.findtext('date') # can be used for Finding.date?
            cve = detail.findtext('./cve/id')
            url = detail.findtext('./referencelist/reference/[type=\'solution\']/../url')
            description = detail.findtext('description')
            mitigation = detail.findtext('solution')
            impact = detail.findtext('information')
            numerical_severity = detail.findtext('cvss_v3_score')
            if numerical_severity:
                score = float(numerical_severity)
                if score < 4:
                    severity = 'Low'
                elif score < 7:
                    severity = 'Medium'
                elif score < 9:
                    severity = 'High'
                else:
                    severity = 'Critical'
                findings.append(Finding(title=title, test=test, cve=cve,
                                        url=url, description=description,
                                        mitigation=mitigation, impact=impact,
                                        severity=severity,
                                        numerical_severity=numerical_severity))
        self._findings = findings

    @property
    def items(self):
        return self._findings
