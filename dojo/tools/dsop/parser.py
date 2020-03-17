import re

import pandas as pd

from dojo.models import Finding

__author__ = 'Matt Sicker'


class DsopParser:
    def __init__(self, file, test):
        self._test = test
        self._items = []
        f = pd.ExcelFile(file)
        self.__parse_disa(pd.read_excel(f, sheet_name='OpenSCAP - DISA Compliance', parse_dates=['scanned_date'],
                                        dtype={'result': 'category', 'severity': 'category'}))
        self.__parse_oval(pd.read_excel(f, sheet_name='OpenSCAP - OVAL Results'))
        self.__parse_twistlock(
            pd.read_excel(f, sheet_name='Twistlock Vulnerability Results', dtype={'severity': 'category'}))
        self.__parse_anchore(pd.read_excel(f, sheet_name='Anchore CVE Results', dtype={'severity': 'category'}))

    def __parse_disa(self, df: pd.DataFrame):
        for row in df.itertuples(index=False):
            if row.result not in ('fail', 'notchecked'):
                continue
            title = row.title
            unique_id = row.ruleid
            if row.severity == 'unknown':
                severity = 'Info'
            else:
                severity = row.severity.title()
            cve = row.identifiers
            references = row.refs
            description = row.desc
            impact = row.rationale
            date = row.scanned_date.date()
            tags = "disa"

            finding = Finding(title=title, date=date, cve=cve, severity=severity, description=description,
                        impact=impact, references=references, test=self._test, unique_id_from_tool=unique_id)
            finding.unsaved_tags = tags
            self._items.append(finding)

    def __parse_oval(self, df: pd.DataFrame):
        severity_pattern = re.compile(r'\((.*)\)')
        for row in df.itertuples(index=False):
            if not row.result or row.result in ('false'):
                continue
            title = row.title
            match = severity_pattern.search(title)
            if match:
                sev = match.group(1)
                if sev == 'Important':
                    severity = 'High'
                elif sev == 'Moderate':
                    severity = 'Medium'
                elif sev == 'None':
                    severity = 'Info'
                else:
                    severity = sev
            else:
                severity = 'Info'
            unique_id = row.id
            cve = row.ref
            tags = "oval"

            finding = Finding(title=title, cve=cve, severity=severity, unique_id_from_tool=unique_id,
                    test=self._test)
            finding.unsaved_tags = tags
            self._items.append(finding)

    def __parse_twistlock(self, df: pd.DataFrame):
        for row in df.itertuples(index=False):
            cve = row.id
            description = row.desc
            mitigation = row.status
            url = row.link
            component_name = row.packageName
            component_version = row.packageVersion
            title = '{}: {} - {}'.format(cve, component_name, component_version)
            if row.severity == 'important':
                severity = 'High'
            elif row.severity == 'moderate':
                severity = 'Medium'
            else:
                severity = row.severity.title()
            severity_justification = row.vecStr
            tags = "twistlock"

            finding = Finding(title=title, cve=cve, url=url, severity=severity, description=description,
                                       severity_justification=severity_justification, test=self._test)
            finding.unsaved_tags = tags
            self._items.append(finding)

    def __parse_anchore(self, df: pd.DataFrame):
        for row in df.itertuples(index=False):
            cve = row.cve
            severity = row.severity
            component = row.vuln
            mitigation = row.fix
            description = "Image affected: {}".format(row.tag)
            title = '{}: {}'.format(cve, component)
            tags = "anchore"

            finding = Finding(title=title, cve=cve, severity=severity,
                                    description=description, test=self._test)
            finding.unsaved_tags = tags
            self._items.append(finding)

    @property
    def items(self):
        return self._items
