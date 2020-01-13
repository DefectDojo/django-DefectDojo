from defusedxml import ElementTree
from dojo.models import Finding, Endpoint


class Outpost24Parser:
    def __init__(self, file, test):
        tree = ElementTree.parse(file)
        items = list()
        for detail in tree.iterfind('//detaillist/detail'):
            title = detail.findtext('name')
            # date = detail.findtext('date') # can be used for Finding.date?
            cve = detail.findtext('./cve/id')
            url = detail.findtext('./referencelist/reference/[type=\'solution\']/../url')
            description = detail.findtext('description')
            mitigation = detail.findtext('solution')
            impact = detail.findtext('information')
            protocol = detail.findtext('./portinfo/service')
            host = detail.findtext('hostname') or detail.findtext('ip')
            port = int(detail.findtext('./portinfo/portnumber'))
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
            else:
                risk = int(detail.findtext('risk'))
                if risk == 0:
                    severity = 'Low'
                elif risk == 1:
                    severity = 'Medium'
                elif risk == 2:
                    severity = 'High'
                else:
                    severity = 'Critical'
            finding = Finding(title=title, test=test, cve=cve, url=url, description=description, mitigation=mitigation,
                              impact=impact, severity=severity, numerical_severity=numerical_severity)
            finding.unsaved_endpoints.append(Endpoint(protocol=protocol, host=host, port=port))
            items.append(finding)
        self._items = items

    @property
    def items(self):
        return self._items
