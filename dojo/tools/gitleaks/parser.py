import hashlib
import json

from dojo.models import Finding


class GitleaksParser(object):
    """
    A class that can be used to parse the Gitleaks JSON report files
    """

    def get_scan_types(self):
        return ["Gitleaks Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Gitleaks Scan findings in JSON format."

    def get_findings(self, filename, test):
        """
        Converts a Gitleaks report to DefectDojo findings
        """
        issues = json.load(filename)
        # empty report are just null object
        if issues is None:
            return list()

        dupes = dict()

        for issue in issues:
            if issue.get('rule'):
                self.get_finding_legacy(issue, test, dupes)
            elif issue.get('Description'):
                self.get_finding_current(issue, test, dupes)
            else:
                raise Exception('Format is not recognized for Gitleaks')

        return list(dupes.values())

    def get_finding_legacy(self, issue, test, dupes):
        line = None
        file_path = issue["file"]
        reason = issue["rule"]
        titleText = "Hard Coded " + reason
        description = "**Commit:** " + issue["commitMessage"].rstrip("\n") + "\n"
        description += "**Commit Hash:** " + issue["commit"] + "\n"
        description += "**Commit Date:** " + issue["date"] + "\n"
        description += "**Author:** " + issue["author"] + " <" + issue["email"] + ">" + "\n"
        description += "**Reason:** " + reason + "\n"
        description += "**Path:** " + file_path + "\n"
        if "lineNumber" in issue:
            description += "**Line:** %i\n" % issue["lineNumber"]
            line = issue["lineNumber"]
        if "operation" in issue:
            description += "**Operation:** " + issue["operation"] + "\n"
        if "leakURL" in issue:
            description += "**Leak URL:** [" + issue["leakURL"] + "](" + issue["leakURL"] + ")\n"
        description += "\n**String Found:**\n\n```\n" + issue["line"].replace(issue["offender"], "REDACTED") + "\n```"

        severity = "High"
        if "Github" in reason or "AWS" in reason or "Heroku" in reason:
            severity = "Critical"

        finding = Finding(
            title=titleText,
            test=test,
            cwe=798,
            description=description,
            severity=severity,
            file_path=file_path,
            line=line,
            dynamic_finding=False,
            static_finding=True,
        )
        # manage tags
        finding.unsaved_tags = issue.get("tags", "").split(', ')

        dupe_key = hashlib.sha256((issue["offender"] + file_path + str(line)).encode("utf-8")).hexdigest()

        if dupe_key not in dupes:
            dupes[dupe_key] = finding

    def get_finding_current(self, issue, test, dupes):
        reason = issue.get('Description')
        line = issue.get('StartLine')
        if line:
            line = int(line)
        else:
            line = 0
        match = issue.get('Match')
        secret = issue.get('Secret')
        file_path = issue.get('File')
        commit = issue.get('Commit')
        # Author and email will not be used because of GDPR
        # author = issue.get('Author')
        # email = issue.get('Email')
        date = issue.get('Date')
        message = issue.get('Message')
        tags = issue.get('Tags')
        ruleId = issue.get('RuleID')

        title = f'Hard coded {reason} found in {file_path}'

        description = ''
        if secret:
            description += f'**Secret:** {secret}\n'
        if match:
            description += f'**Match:** {match}\n'
        if message:
            if len(message.split("\n")) > 1:
                description += "**Commit message:**" + "\n```\n" + message.replace('```', '\\`\\`\\`') + "\n```\n"
            else:
                description += f'**Commit message:** {message}\n'
        if commit:
            description += f'**Commit hash:** {commit}\n'
        if date:
            description += f'**Commit date:** {date}\n'
        if ruleId:
            description += f'**Rule Id:** {ruleId}'
        if description[-1] == '\n':
            description = description[:-1]

        severity = "High"

        dupe_key = hashlib.md5((title + secret + str(line)).encode("utf-8")).hexdigest()

        if dupe_key in dupes:
            finding = dupes[dupe_key]
            finding.description = finding.description + '\n\n***\n\n' + description
            finding.nb_occurences += 1
            dupes[dupe_key] = finding
        else:
            finding = Finding(
                title=title,
                test=test,
                cwe=798,
                description=description,
                severity=severity,
                file_path=file_path,
                line=line,
                dynamic_finding=False,
                static_finding=True,
                nb_occurences=1,
            )
            if tags:
                finding.unsaved_tags = tags
            dupes[dupe_key] = finding
