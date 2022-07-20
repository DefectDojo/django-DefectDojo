import json
import hashlib

from dojo.models import Finding


class PWNSASTParser(object):
    """
    A class that can be used to parse pwn_sast source code scanning results in JSON format.  See https://github.com/0dayinc/pwn for additional details.
    """

    def get_scan_types(self):
        return ["PWN SAST"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import pwn_sast Driver findings in JSON format."

    def get_findings(self, filename, test):

        results = json.load(filename)

        if results is not None:
            report_name = results.get("report_name")
            data_arr = results.get("data")

            findings = {}

            for data_hash in data_arr:
                timestamp = data_hash.get("timestamp")

                security_references = data_hash.get("security_references")
                if security_references is not None:
                    sast_module = security_references["sast_module"]
                    section = security_references["section"]
                    nist_800_53_uri = security_references["nist_800_53_uri"]
                    cwe_id = security_references["cwe_id"]
                    cwe_uri = security_references["cwe_uri"]
                else:
                    sast_module = None
                    section = None
                    nist_800_53_uri = None
                    cwe_id = None
                    cwe_uri = None

                filename_hash = data_hash.get("filename")
                if filename_hash is not None:
                    git_repo_root_uri = filename_hash["git_repo_root_uri"]
                    offending_file = filename_hash["entry"]
                else:
                    git_repo_root_uri = None
                    offending_file = None

                line_no_and_contents = data_hash.get("line_no_and_contents")
                test_case_filter = data_hash.get("test_case_filter")
                steps_to_reproduce = "\n".join([
                    "Install pwn_sast Driver via: https://github.com/0dayinc/pwn#installation",
                    "Execute the pwn_sast Driver via:",
                    f"```pwn_sast --dir-path . --uri-source-root {git_repo_root_uri} -s```"
                ])

                for line in line_no_and_contents:
                    offending_uri = f"{git_repo_root_uri}/{offending_file}"
                    line_no = line.get("line_no")
                    contents = line.get("contents")
                    author = line.get("author")
                    severity = 'Info'
                    description = "\n".join([
                        f"SAST Module: {sast_module}",
                        f"Offending URI: {offending_uri}",
                        f"Line: {line_no}",
                        f"Committed By: {author}",
                        "Line Contents:",
                        f"```{contents}```"
                    ])

                    impact = "\n".join([
                        f"Security Control Impacted: {section}",
                        f"NIST 800-53 Security Control Details: {nist_800_53_uri}",
                        f"CWE Details: {cwe_uri}"
                    ])

                    mitigation = "\n".join([
                        f"NIST 800-53 Security Control Details / Mitigation Strategy: {nist_800_53_uri}",
                    ])

                    unique_finding_key = hashlib.sha256(
                        (offending_uri + contents).encode("utf-8")
                    ).hexdigest()

                    if unique_finding_key in findings:
                        finding = findings[unique_finding_key]
                        finding.nb_occurences += 1
                    else:
                        finding = Finding(
                            title=f"Source Code Anti-Pattern Discovered in {offending_uri} Line: {line_no}",
                            test=test,
                            severity=severity,
                            description=description,
                            impact=impact,
                            mitigation=mitigation,
                            static_finding=True,
                            dynamic_finding=False,
                            cwe=cwe_id,
                            nb_occurences=1,
                            steps_to_reproduce=steps_to_reproduce,
                            file_path=offending_file
                        )
                        findings[unique_finding_key] = finding

            return list(findings.values())
