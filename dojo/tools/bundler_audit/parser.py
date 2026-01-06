__author__ = "jaguasch"

import hashlib
from datetime import datetime

from dojo.models import Finding


class BundlerAuditParser:
    def get_scan_types(self):
        return ["Bundler-Audit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Bundler-Audit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "'bundler-audit check' output (in plain text)"

    def get_findings(self, filename, test):
        lines = filename.read()
        if isinstance(lines, bytes):
            lines = lines.decode("utf-8")  # passes in unittests, but would fail in production

        dupes = {}
        find_date = datetime.now()
        warnings = lines.split("\n\n")

        for warning in warnings:
            if not warning.startswith("Name"):
                continue
            advisory_id = None
            gem_report_fields = warning.split("\n")
            for field in gem_report_fields:
                if field.startswith("Name"):
                    gem_name = field.replace("Name: ", "")
                elif field.startswith("Version"):
                    gem_version = field.replace("Version: ", "")
                elif field.startswith("Advisory"):
                    advisory_id = field.replace("Advisory: ", "")
                elif field.startswith("CVE"):
                    advisory_id = field.replace("CVE: ", "")
                elif advisory_id is None and field.startswith("GHSA"):
                    advisory_id = field.replace("GHSA: ", "")
                elif field.startswith("Criticality"):
                    criticality = field.replace("Criticality: ", "")
                    sev = "Medium" if criticality.lower() == "unknown" else criticality
                elif field.startswith("URL"):
                    advisory_url = field.replace("URL: ", "")
                elif field.startswith("Title"):
                    advisory_title = field.replace("Title: ", "")
                elif field.startswith("Solution"):
                    advisory_solution = field.replace("Solution: ", "")

            title = (
                "Gem "
                + gem_name
                + ": "
                + advisory_title
                + " ["
                + advisory_id
                + "]"
            )
            findingdetail = (
                "Gem **" + gem_name + "** has known security issues:\n"
            )
            findingdetail += "**Name**: " + gem_name + "\n"
            findingdetail += "**Version**: " + gem_version + "\n"
            findingdetail += "**Advisory**: " + advisory_id + "\n"
            mitigation = advisory_solution
            references = advisory_url
            fingerprint = (
                "bundler-audit" + gem_name + gem_version + advisory_id + sev
            )
            dupe_key = hashlib.md5(fingerprint.encode("utf-8"), usedforsecurity=False).hexdigest()
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
                )
                if advisory_id:
                    find.unsaved_vulnerability_ids = [advisory_id]

                dupes[dupe_key] = find

        return list(dupes.values())
