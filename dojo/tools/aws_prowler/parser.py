# For Prowler CSV Export
# Based on:
# PROWLER_VERSION=2.4.0-07042021

import re
from datetime import datetime
import sys
import io
import csv
import textwrap
import hashlib

from dojo.models import Finding


class AWSProwlerParser(object):

    def get_scan_types(self):
        return ["AWS Prowler Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "AWS Prowler Scan"

    def get_description_for_scan_types(self, scan_type):
        return "AWS Security Hub exports in JSON format."

    def get_findings(self, filename, test):
        content = filename.read()
        if type(content) is bytes:
            content = content.decode('utf-8')
        csv.field_size_limit(int(sys.maxsize / 10))  # the request/resp are big
        reader = csv.DictReader(io.StringIO(content))
        dupes = dict()

        find_date = datetime.now()
        account = None

        for row in reader:
            # Getting all available fields from the Prowler CSV
            # Fields in order of appearence
            profile = row.get('PROFILE')
            account = row.get('ACCOUNT_NUM')
            region = row.get('REGION')
            title_id = row.get('TITLE_ID')
            result = row.get('CHECK_RESULT')
            scored = row.get('ITEM_SCORED')
            level = row.get('ITEM_LEVEL')
            title_text = row.get('TITLE_TEXT')
            result_extended = row.get('CHECK_RESULT_EXTENDED')
            asff_compliance_type = row.get('CHECK_ASFF_COMPLIANCE_TYPE')
            severity = row.get('SEVERITY')
            aws_service_name = row.get('CHECK_SERVICENAME')
            asff_resource_type = row.get('CHECK_ASFF_RESOURCE_TYPE')
            asff_type = row.get('CHECK_ASFF_TYPE')
            impact = row.get('CHECK_RISK')
            mitigation = row.get('CHECK_REMEDIATION')
            documentation = row.get('CHECK_DOC')
            security_domain = row.get('CHECK_CAF_EPIC')
            # get prowler check number, usefull for exceptions
            prowler_check_number = re.search(r'\[(.*?)\]', title_text).group(1)
            # remove '[check000] ' at the start of each title
            title = re.sub(r'\[.*\]\s', '', result_extended)
            control = re.sub(r'\[.*\]\s', '', title_text)
            sev = self.getCriticalityRating(result, level, severity)
            if result == "INFO" or result == "PASS":
                active = False
            else:
                active = True

            # creating description early will help with duplication control
            if not level:
                level = ""
            else:
                level = ", " + level
            description = "**Issue:** " + str(result_extended) + \
                "\n**Control:** " + str(control) + \
                "\n**AWS Account:** " + str(account) + " | **Region:** " + str(region) + \
                "\n**CIS Control:** " + str(title_id) + str(level) + \
                "\n**Prowler check:** " + str(prowler_check_number) + \
                "\n**AWS Service:** " + str(aws_service_name) + \
                "\n**ASFF Resource Type:** " + str(asff_resource_type) + \
                "\n**ASFF Type:** " + str(asff_type) + \
                "\n**ASFF Compliance Type:** " + str(asff_compliance_type) + \
                "\n**Security Domain:** " + str(security_domain)

            # improving key to get duplicates
            dupe_key = hashlib.sha256(
                (sev + '|' + region + '|' + result_extended).encode('utf-8')).hexdigest()
            if dupe_key in dupes:
                find = dupes[dupe_key]
                if description is not None:
                    find.description += description + "\n\n"
                find.nb_occurences += 1
            else:
                find = Finding(
                    active=active,
                    title=textwrap.shorten(result_extended, 150),
                    cwe=1032,  # Security Configuration Weaknesses, would like to fine tune
                    test=test,
                    description=description,
                    severity=sev,
                    references=documentation,
                    date=find_date,
                    dynamic_finding=True,
                    nb_occurences=1,
                    mitigation=mitigation,
                    impact=impact,
                )
                dupes[dupe_key] = find

        return list(dupes.values())

    def formatview(self, depth):
        if depth > 1:
            return "* "
        else:
            return ""

    # Criticality rating
    def getCriticalityRating(self, result, level, severity):
        criticality = "Info"
        if result == "INFO" or result == "PASS":
            criticality = "Info"
        elif result == "FAIL":
            if severity:
                # control is failing but marked as Info so we want to mark as
                # Low to appear in the Dojo
                if severity == "Informational":
                    return "Low"
                return severity
            else:
                if level == "Level 1":
                    criticality = "Critical"
                else:
                    criticality = "High"

        return criticality
