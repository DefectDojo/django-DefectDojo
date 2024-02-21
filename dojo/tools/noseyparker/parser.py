import hashlib
import json

from datetime import datetime
from dojo.models import Finding


class NoseyParkerParser(object):
    """
    Scanning secrets from repos
    """

    def get_scan_types(self):
        return ["Nosey Parker Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Nosey Parker Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Nosey Parker report file can be imported in JSON Lines format (option --jsonl). " \
               "Supports v0.16.0 of https://github.com/praetorian-inc/noseyparker"

    def get_findings(self, file, test):
        """
        Returns findings from jsonlines file and uses filter
        to skip findings and determine severity
        """
        dupes = {}

        # Turn JSONL file into DataFrame
        if file is None:
            return
        elif file.name.lower().endswith(".jsonl"):
            # Process JSON lines into Dict
            data = [json.loads(line) for line in file]

            # Check for empty file
            if len(data[0]) == 0:
                return []

            # Parse through each secret in each JSON line
            for line in data:
                # Set rule to the current secret type (e.g. AWS S3 Bucket)
                try:
                    rule_name = line['rule_name']
                    secret = line['match_content']
                except Exception:
                    raise ValueError("Invalid Nosey Parker data, make sure to use Nosey Parker v0.16.0")

                # Set Finding details
                for match in line['matches']:
                    # The following path is to account for the variability in the JSON lines output
                    num_elements = len(match['provenance']) - 1
                    json_path = match['provenance'][num_elements]

                    title = f"Secret(s) Found in Repository with Commit ID {json_path['commit_provenance']['commit_metadata']['commit_id']}"
                    filepath = json_path['commit_provenance']['blob_path']
                    line_num = match['location']['source_span']['start']['line']
                    description = f"Secret found of type:   {rule_name} \n" \
                                  f"SECRET starts with:  '{secret[:3]}' \n" \
                                  f"Committer Name: {json_path['commit_provenance']['commit_metadata']['committer_name']}  \n" \
                                  f"Committer Email: {json_path['commit_provenance']['commit_metadata']['committer_email']} \n" \
                                  f"Commit ID: {json_path['commit_provenance']['commit_metadata']['commit_id']}  \n" \
                                  f"Location: {filepath} line #{line_num} \n " \
                                  f"Line #{line_num} \n " \
                                  f"Code Snippet Containing Secret: {match['snippet']['before']}***SECRET***{match['snippet']['after']} \n"

                    # Internal de-duplication
                    key = hashlib.md5((filepath + "|" + secret + "|" + str(line_num)).encode("utf-8")).hexdigest()

                    # If secret already exists with the same filepath/secret/linenum
                    if key in dupes:
                        finding = dupes[key]
                        finding.nb_occurences += 1
                        dupes[key] = finding
                    else:
                        dupes[key] = True
                        # Create Finding object
                        finding = Finding(
                            test=test,
                            cwe=798,
                            title=title,
                            description=description,
                            severity='High',
                            mitigation="Reset the account/token and remove from source code. Store secrets/tokens/passwords in secret managers or secure vaults.",
                            date=datetime.today().strftime("%Y-%m-%d"),
                            verified=False,
                            active=True,
                            is_mitigated=False,
                            file_path=filepath,
                            line=line_num,
                            static_finding=True,
                            nb_occurences=1,
                            dynamic_finding=False

                        )
                        dupes[key] = finding
        else:
            raise ValueError("JSON lines format not recognized (.jsonl file extension). Make sure to use Nosey Parker v0.16.0")

        return list(dupes.values())
