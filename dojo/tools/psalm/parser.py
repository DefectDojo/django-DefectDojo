from dojo.tools.sarif.parser import SarifParser


class PsalmParser(SarifParser):

    """
    Psalm is a static analysis tool for PHP.

    Psalm writes SARIF with ``--report=<file>.sarif``, so this reuses DefectDojo's SARIF
    parsing. Psalm sorts every issue into one of two levels, error and info, which it emits as
    the SARIF levels ``error`` and ``note``; the shared parser turns those into High and Info.
    Which level a given issue type lands on is driven by the ``errorLevel`` in psalm.xml, so
    the severity of an import reflects the project's own Psalm configuration.
    """

    def get_scan_types(self):
        return ["Psalm Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Psalm Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the SARIF report produced by `psalm --report=results.sarif`."

    def get_finding_title(self, result, rule, location):
        """
        Lead the title with Psalm's issue type rather than only the message.

        Psalm's SARIF ``ruleId`` is a bare number (its documentation shortcode), and the
        message alone does not name the issue type. The issue type is the identifier that
        appears in psalm.xml, in baselines and in ``--issues=``, so it belongs in the title.
        """
        issue_type = (rule or {}).get("name")
        message = None
        if "message" in result:
            message = result["message"].get("text")
        if issue_type and message:
            return f"{issue_type}: {message}"
        return super().get_finding_title(result, rule, location)

    def customize_finding(self, finding, result, rule, location):
        """
        Track findings by Psalm's issue type, keeping the numeric shortcode in the description.

        The shared parser sets ``vuln_id_from_tool`` from the SARIF ``ruleId``, which for Psalm
        is the numeric shortcode. The issue type name is the stable, human-meaningful
        identifier, so it is a better key for deduplication and for rules built on top.
        """
        issue_type = (rule or {}).get("name")
        if issue_type:
            shortcode = result.get("ruleId")
            finding.vuln_id_from_tool = issue_type
            if shortcode:
                finding.description = "\n".join(
                    [finding.description or "", f"**Psalm shortcode:** {shortcode}"],
                ).strip()
