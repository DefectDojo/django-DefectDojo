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
        return "Nosey Parker report file can be imported in JSON Lines format (option --jsonl)."

    def get_findings(self, file, test, reporter):
        """
        Returns findings from jsonlines file
        """
        dupes = {}
        # Turn JSONL file into DataFrame
        if file.name.lower().endswith(".jsonl") or file.name.lower().endswith(".json"):
            # Process jsonlines into Dict
            data = [json.loads(line) for line in file]

            # Check for empty file
            if len(len(data)) == 0:
                return []

            # Parse through each secret of each Json line
            for item in data:
                # Set rule to the current secret type (e.g AWS S3 Bucket)
                key = item['rule_name']
                # Number of identical secret matches
                num_matches = item['num_matches']
                severity = "High"

                # First finding in json list
                first_finding = item['matches'][0]

                # Set Finding details
                title = f"Secret(s) Found in Repository with Commit ID {first_finding['blob_id']}"
                description = f"Secret found of type:   {key} \n" \
                              f"SECRET starts with:  {secret[:3]} on line number {line_num} \n" \
                              f"This secret was found {num_matches} time(s) \n" \
                              f"**Committer Name: ** {first_finding['provenance']['commit_provenance']['committer_name']}  \n" \
                              f"**Committer Email: ** {first_finding['provenance']['commit_provenance']['committer_email']} \n"

                line_num = first_finding['location']['source_span']['start']['line']
                secret = item['match_content']
                filepath = first_finding['provenance.path']
                reproduce = f"**First Occurrence of secret: ** \n" \
                            f"Snippet: {first_finding['snippet']['before']}***SECRET***{first_finding['snippet']['after']} \n" \
                            f"Location: {filepath} line #{line_num}"
                description += reproduce

                # Internal de-duplication
                dupe_key = hashlib.sha256(str(filepath + secret).encode('utf-8')).hexdigest()
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if finding.description:
                        find.description += "\n" + finding.description
                    finding.nb_occurences += 1
                    dupes[dupe_key] = find
                else:
                    dupes[dupe_key] = True
                    # Create Finding object
                    finding = Finding(
                        test=test,
                        cwe=798,
                        title=title,
                        description=description,
                        steps_to_reproduce=reproduce,
                        severity=severity,
                        mitigation="Please reset the account/token and remove ALL occurences of this secret from source code. "
                                   "Store secrets/tokens/passwords in secret managers or secure vaults.",
                        reporter=reporter,
                        date=datetime.today().strftime("%Y-%m-%d"),
                        verified='false',
                        active='true',
                        is_mitigated='false',
                        file_path=filepath,
                        line=line_num,
                        static_finding=True,
                        dynamic_finding=False

                    )
                    dupes[dupe_key] = finding
            else:
                raise ValueError("Format is not recognized for NoseyParker")



    def get_findings(self, file, test, filter, reporter):
        """
        Returns findings from jsonlines file and uses filter
        to skip findings and determine severity
        """
        dupes = {}

        # Filter
        filter_dict = self.parse_filter(filter)

        # Turn JSONL file into DataFrame
        if file.name.lower().endswith(".jsonl") or file.name.lower().endswith(".json"):
            # Process jsonlines into Dict
            data = [json.loads(line) for line in file]

            # Check for empty file
            if len(len(data)) == 0:
                return []


            # Parse through each secret of each Json line
            for item in data:
                # Set rule to the current secret type (e.g AWS S3 Bucket)
                key = item['rule_name']
                # Number of identical secret matches
                num_matches = item['num_matches']
                severity = "High"

                # Check if Filter dictionary indicates to Skip finding
                if key in filter_dict:
                    if filter_dict[key]['Skip'] == "True":
                        return []
                    else:
                        # Get severity from filter json
                        severity = filter_dict[key]['Priority']

                # First finding in json list
                first_finding = item['matches'][0]

                # Set Finding details
                title = f"Secret(s) Found in Repository with Commit ID {first_finding['blob_id']}"
                description = f"Secret found of type:   {key} \n" \
                              f"SECRET starts with:  {secret[:3]} on line number {line_num} \n" \
                              f"This secret was found {num_matches} time(s) \n" \
                              f"**Committer Name: ** {first_finding['provenance']['commit_provenance']['committer_name']}  \n" \
                              f"**Committer Email: ** {first_finding['provenance']['commit_provenance']['committer_email']} \n"

                line_num = first_finding['location']['source_span']['start']['line']
                secret = item['match_content']
                filepath = first_finding['provenance.path']
                reproduce = f"**First Occurrence of secret: ** \n" \
                            f"Snippet: {first_finding['snippet']['before']}***SECRET***{first_finding['snippet']['after']} \n" \
                            f"Location: {filepath} line #{line_num}"
                description += reproduce

                # Internal de-duplication
                dupe_key = hashlib.sha256(str(filepath + secret).encode('utf-8')).hexdigest()
                if dupe_key in dupes:
                    find = dupes[dupe_key]
                    if finding.description:
                        find.description += "\n" + finding.description
                    finding.nb_occurences += 1
                    dupes[dupe_key] = find
                else:
                    dupes[dupe_key] = True
                    # Create Finding object
                    finding = Finding(
                        test=test,
                        cwe=798,
                        title=title,
                        description=description,
                        steps_to_reproduce=reproduce,
                        severity=severity,
                        mitigation="Please reset the account/token and remove ALL occurences of this secret from source code. "
                                   "Store secrets/tokens/passwords in secret managers or secure vaults.",
                        reporter=reporter,
                        date=datetime.today().strftime("%Y-%m-%d"),
                        verified='false',
                        active='true',
                        is_mitigated='false',
                        file_path=filepath,
                        line=line_num,
                        static_finding=True,
                        dynamic_finding=False

                    )
                    dupes[dupe_key] = finding
        else:
            raise ValueError("Format is not recognized for NoseyParker")

        return list(dupes.values())

    def parse_filter(self, filter_file):
        # Parse Filter JSON file into Dictionary

        filter_dict = json.load(filter_file)
        return filter_dict
