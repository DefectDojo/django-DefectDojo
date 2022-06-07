__author__ = 'jaguasch'

import hashlib
from datetime import datetime

from dojo.models import Finding


class BundlerAuditParser(object):

    def get_scan_types(self):
        return ["Bundler-Audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Bundler-Audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "'bundler-audit check' output (in plain text)"

    def get_findings(self, filename, test):
        lines = filename.read()
        dupes = dict()
        find_date = datetime.now()
        warnings = lines.split('\n\n')

        for warning in warnings:
            if not warning.startswith('Name'):
                continue
            advisory_cve = None
            gem_report_fields = warning.split('\n')
            for field in gem_report_fields:
                if field.startswith('Name'):
                    gem_name = field.replace('Name: ', '')
                elif field.startswith('Version'):
                    gem_version = field.replace('Version: ', '')
                elif field.startswith('Advisory'):
                    advisory_cve = field.replace('Advisory: ', '')
                elif field.startswith('CVE'):
                    advisory_cve = field.replace('CVE: ', '')
                elif field.startswith('Criticality'):
                    criticality = field.replace('Criticality: ', '')
                    if criticality.lower() == 'unknown':
                        sev = "Medium"
                    else:
                        sev = criticality
                elif field.startswith('URL'):
                    advisory_url = field.replace('URL: ', '')
                elif field.startswith('Title'):
                    advisory_title = field.replace('Title: ', '')
                elif field.startswith('Solution'):
                    advisory_solution = field.replace('Solution: ', '')

            title = "Gem " + gem_name + ": " + advisory_title + " [" + advisory_cve + "]"
            findingdetail = "Gem **" + gem_name + "** has known security issues:\n"
            findingdetail += '**Name**: ' + gem_name + '\n'
            findingdetail += '**Version**: ' + gem_version + '\n'
            findingdetail += '**Advisory**: ' + advisory_cve + '\n'
            mitigation = advisory_solution
            references = advisory_url
            fingerprint = "bundler-audit" + gem_name + gem_version + advisory_cve + sev
            dupe_key = hashlib.md5(fingerprint.encode("utf-8")).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
            else:
                dupes[dupe_key] = True

                find = Finding(
                    title=title,
                    test=test,
                    description=findingdetail,
                    severity=sev,
                    mitigation=mitigation,
                    references=references,
                    date=find_date,
                    static_finding=True,
                    dynamic_finding=False,
                    component_name=gem_name,
                    component_version=gem_version,
                    cve=advisory_cve,
                )

                dupes[dupe_key] = find

        return list(dupes.values())
