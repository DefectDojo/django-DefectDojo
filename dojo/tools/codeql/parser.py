from dojo.tools.sarif.parser import SarifParser


class CodeQLParser(SarifParser):

    """
    CodeQL is GitHub's semantic code analysis engine.

    SARIF is CodeQL's native output format, so this reuses DefectDojo's SARIF parsing. CodeQL
    populates two things the shared parser already understands: a ``security-severity`` rule
    property carrying a CVSS-style score for security queries, and ``external/cwe/cwe-NNN``
    rule tags. Severity therefore comes from CodeQL's own score rather than from a fixed map.
    """

    def get_scan_types(self):
        return ["CodeQL Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "CodeQL Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the SARIF report produced by "
            "`codeql database analyze <database> --format=sarifv2.1.0 --output=results.sarif`."
        )

    def get_finding_title(self, result, rule, location):
        """
        Title findings with the query id and the query's short description.

        A CodeQL result message describes the data flow that was found ("This SQL query
        depends on a user-provided value") and is identical for every finding the same query
        raises, so on its own it does not say which query fired. The query id is what teams
        triage, silence and track on, so it leads.
        """
        rule_id = result.get("ruleId")
        short_description = None
        if rule is not None and "shortDescription" in rule:
            short_description = rule["shortDescription"].get("text")
        if rule_id and short_description:
            return f"{rule_id}: {short_description}"
        return super().get_finding_title(result, rule, location)

    def customize_finding(self, finding, result, rule, location):
        """Record the query's own confidence and problem class, which SARIF has no field for."""
        properties = (rule or {}).get("properties", {})
        details = [
            f"**{label}:** {properties[key]}"
            for key, label in (
                ("precision", "Query precision"),
                ("kind", "Problem kind"),
                ("security-severity", "CodeQL security severity"),
            )
            if properties.get(key)
        ]
        if details:
            finding.description = "\n".join([finding.description or "", *details]).strip()
