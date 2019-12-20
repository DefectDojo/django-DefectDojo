import json
import hashlib

__author__ = 'Kirill Gotsman'


class HackerOneJSONParser(object):
    """
    A class that can be used to parse the Get All Reports JSON export from HackerOne API.
    """

    def __init__(self, file, test):
        """
        Converts a HackerOne reports to a DefectDojo finding
        """
        self.dupes = dict()
        # Start with an empty findings
        self.items = ()
        # Exit if file is not provided
        if file is None:
            return
        # Load the contents of the JSON file into a dictionary
        data = file.read()
        try:
            tree = json.loads(str(data, 'utf-8'))
        except:
            tree = json.loads(data)
        # Conver JSON  report to DefectDojo format
        for content in tree["data"]:
            # Build the title of the Dojo finding
            title = "#" + content["id"] + " " + content["attributes"]["title"]
            # Build the description of the Dojo finding
            description = content["attributes"]["vulnerability_information"]

            # Build the severity of the Dojo finding
            try:
                severity = content["relationships"]["severity"]["data"]["attributes"]["rating"].capitalize()
                if severity not in ["Low", "Medium", "Hight", "Critical"]:
                    severity = "Info"
            except:
                severity = "Info"
            # Build the references of the Dojo finding
            ref_link = "https://hackerone.com/reports/{}".format(content.get("id"))
            references = "[{}]({})".format(ref_link, ref_link)

            # Set active state of the Dojo finding
            if content["attributes"]["state"] in ["triaged", "new"]:
                active = True
            else:
                active = False

            # Set CWE of the Dojo finding
            try:
                cwe = int(content["relationships"]["weakness"]["data"]["attributes"]["external_id"][4:])
            except:
                cwe = 0

            dupe_key = hashlib.md5(str(references + title).encode('utf-8')).hexdigest()
            if dupe_key in self.dupes:
                finding = self.dupes[dupe_key]
                if finding.references:
                    finding.references = finding.references
                self.dupes[dupe_key] = finding
            else:
                self.dupes[dupe_key] = True

                # Build and return Finding model
                finding = Finding(
                    title=title,
                    test=test,
                    active=active,
                    description=description,
                    severity=severity,
                    numerical_severity=Finding.get_numerical_severity(severity),
                    mitigation="See description",
                    impact="No impact provided",
                    references=references,
                    cwe=cwe,
                    dynamic_finding=False,)
                finding.unsaved_endpoints = list()
                self.dupes[dupe_key] = finding
            self.items = self.dupes.values()
