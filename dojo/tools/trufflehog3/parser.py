import hashlib
import json

from dojo.models import Finding


class TruffleHog3Parser(object):

    def get_scan_types(self):
        return ["Trufflehog3 Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Trufflehog3 Scan"

    def get_description_for_scan_types(self, scan_type):
        return "JSON Output of Trufflehog3, a fork of TruffleHog located at https://github.com/feeltheajf/truffleHog3"

    def get_findings(self, filename, test):
        data = json.load(filename)

        dupes = dict()

        for json_data in data:
            if json_data.get('reason'):
                self.get_finding_legacy(json_data, test, dupes)
            elif json_data.get('rule'):
                self.get_finding_current(json_data, test, dupes)
            else:
                raise Exception('Format is not recognized for Trufflehog3')

        return list(dupes.values())

    def get_finding_legacy(self, json_data, test, dupes):
        file = json_data["path"]

        reason = json_data["reason"]
        titleText = "Hard Coded " + reason + " in: " + file

        description = ""
        description = "**Commit:** " + str(json_data.get("commit")).split("\n")[0] + "\n"
        description += "\n```\n" + str(json_data.get("commit")).replace('```', '\\`\\`\\`') + "\n```\n"
        description += "**Commit Hash:** " + str(json_data.get("commitHash")) + "\n"
        description += "**Commit Date:** " + json_data["date"] + "\n"
        description += "**Branch:** " + str(json_data.get("branch")) + "\n"
        description += "**Reason:** " + json_data["reason"] + "\n"
        description += "**Path:** " + file + "\n"

        severity = "High"
        if reason == "High Entropy":
            severity = "Info"
        elif "Oauth" in reason or "AWS" in reason or "Heroku" in reason:
            severity = "Critical"
        elif reason == "Generic Secret":
            severity = "Medium"

        strings_found = ""
        for string in json_data["stringsFound"]:
            strings_found += string + "\n"

        dupe_key = hashlib.md5((file + reason).encode("utf-8")).hexdigest()
        description += "\n**Strings Found:**\n```\n" + strings_found + "\n```\n"

        if dupe_key in dupes:
            finding = dupes[dupe_key]
            finding.description = finding.description + description
            finding.nb_occurences += 1
            dupes[dupe_key] = finding
        else:
            dupes[dupe_key] = True

            finding = Finding(title=titleText,
                                test=test,
                                cwe=798,
                                description=description,
                                severity=severity,
                                mitigation="Secrets and passwords should be stored in a secure vault and/or secure storage.",
                                impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                                file_path=file,
                                line=0,  # setting it to a fake value to activate deduplication
                                dynamic_finding=False,
                                static_finding=True,
                                nb_occurences=1)
            dupes[dupe_key] = finding

    def get_finding_current(self, json_data, test, dupes):
        message = json_data['rule'].get('message')
        severity = json_data['rule'].get('severity')
        if severity:
            severity = severity.capitalize()
        file = json_data.get('path')
        line = json_data.get('line')
        if line:
            line = int(line)
        else:
            line = 0
        secret = json_data.get('secret')
        context = json_data.get('context')
        id = json_data.get('id')
        branch = json_data.get('branch')
        commit_message = json_data.get('message')
        # Author will not be used because of GDPR
        # author = json_data.get('author')
        commit = json_data.get('commit')
        date = json_data.get('date')

        title = f'{message} found in {file}'

        description = f'**Secret:** {secret}\n'
        if context:
            description += '**Context:**\n'
            for key in context:
                description += f'    {key}: {context[key]}\n'
        if branch:
            description += f'**Branch:** {branch}\n'
        if commit_message:
            if len(commit_message.split("\n")) > 1:
                description += "**Commit message:** " + "\n```\n" + commit_message.replace('```', '\\`\\`\\`') + "\n```\n"
            else:
                description += f'**Commit message:** {commit_message}\n'
        if commit:
            description += f'**Commit hash:** {commit}\n'
        if date:
            description += f'**Commit date:** {date}\n'
        if description[-1] == '\n':
            description = description[:-1]

        dupe_key = hashlib.md5((title + secret + severity + str(line)).encode("utf-8")).hexdigest()

        if dupe_key in dupes:
            finding = dupes[dupe_key]
            finding.description = finding.description + '\n\n***\n\n' + description
            finding.nb_occurences += 1
            dupes[dupe_key] = finding
        else:
            finding = Finding(title=title,
                              test=test,
                              cwe=798,
                              description=description,
                              severity=severity,
                              mitigation="Secrets and passwords should be stored in a secure vault or secure storage.",
                              impact="This weakness can lead to the exposure of resources or functionality to unintended actors, possibly providing attackers with sensitive information or even execute arbitrary code.",
                              file_path=file,
                              line=line,
                              dynamic_finding=False,
                              static_finding=True,
                              nb_occurences=1)
            dupes[dupe_key] = finding
