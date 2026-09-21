import json

from dojo.models import Finding


class PHPStanParser:

    """
    Parser for PHPStan, a static analysis tool for PHP.

    ``phpstan analyse --error-format=json`` writes a single document with a ``files`` map keyed
    by path, each holding the diagnostics for that file, plus a top level ``errors`` list for
    problems that are not tied to a file at all.
    """

    # PHPStan has no severity scale: at a given analysis level a thing is either an error or it
    # is not reported. It does however mark each diagnostic as ignorable or not, and separates
    # file diagnostics from analysis-level failures, and those two distinctions carry real
    # weight -- see the docs page for the reasoning.
    SEVERITY_ANALYSIS_ERROR = "High"
    SEVERITY_NOT_IGNORABLE = "Medium"
    SEVERITY_IGNORABLE = "Low"

    def get_scan_types(self):
        return ["PHPStan Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import PHPStan reports in JSON format, generated with 'phpstan analyse --error-format=json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []

        for file_path, file_report in (data.get("files") or {}).items():
            findings.extend(
                self._file_finding(message, file_path, test)
                for message in file_report.get("messages", [])
            )

        findings.extend(self._analysis_finding(error, test) for error in data.get("errors") or [])
        return findings

    def _file_finding(self, message, file_path, test):
        identifier = message.get("identifier")
        text = message.get("message", "")
        ignorable = message.get("ignorable", True)

        description = [text] if text else []
        if identifier:
            description.append(f"**Identifier:** {identifier}")
        description.append(f"**Ignorable:** {ignorable}")
        if message.get("tip"):
            description.append(f"**Tip:** {message['tip']}")

        return Finding(
            title=f"{identifier}: {text}" if identifier else text,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY_IGNORABLE if ignorable else self.SEVERITY_NOT_IGNORABLE,
            file_path=file_path,
            line=message.get("line"),
            vuln_id_from_tool=identifier,
            static_finding=True,
            dynamic_finding=False,
        )

    def _analysis_finding(self, error, test):
        """A top level error means PHPStan could not complete the analysis, not that code is wrong."""
        return Finding(
            title=f"PHPStan analysis error: {error}",
            test=test,
            description="\n".join([
                str(error),
                (
                    "This error is reported outside of any file. PHPStan raises these when it "
                    "cannot complete the analysis, for example on a configuration problem or an "
                    "unreadable path, which means part of the codebase may not have been "
                    "analysed at all."
                ),
            ]),
            severity=self.SEVERITY_ANALYSIS_ERROR,
            static_finding=True,
            dynamic_finding=False,
        )
