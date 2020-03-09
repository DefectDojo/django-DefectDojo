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
                pass
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
            self._items.append(
                Finding(title=title, date=date, cve=cve, severity=severity, description=description,
                        impact=impact, references=references, test=self._test, unique_id_from_tool=unique_id))

    def __parse_oval(self, df: pd.DataFrame):
        severity_pattern = re.compile(r'\((.*)\)')
        for row in df.itertuples(index=False):
            if not row.result:
                pass
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
            self._items.append(
                Finding(title=title, cve=cve, severity=severity, unique_id_from_tool=unique_id, test=self._test))

    def __parse_twistlock(self, df: pd.DataFrame):
        for row in df.itertuples(index=False):
            if row.status != 'affected':
                pass
            cve = row.cve
            description = row.desc
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
            self._items.append(Finding(title=title, cve=cve, url=url, severity=severity, description=description,
                                       severity_justification=severity_justification, test=self._test))

    def __parse_anchore(self, df: pd.DataFrame):
        for row in df.itertuples(index=False):
            tag = row.tag
            cve = row.cve
            severity = row.severity
            component = row.vuln
            title = '{}: {}'.format(cve, component)
            self._items.append(Finding(title=title, cve=cve, severity=severity, impact=tag, test=self._test))

    @property
    def items(self):
        return self._items
