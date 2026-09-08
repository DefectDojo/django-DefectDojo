from contextlib import suppress
from datetime import date as _date

from dojo.tools.hiddenlayer.parser import SarifConnectorFindings


class ZimperiumParser(SarifConnectorFindings):

    """
    Parses a Zimperium zScan (MAPS) assessment SARIF report.

    Mirrors pkg/tools/zimperium/connector field for field so a file import and an API sync deduplicate
    against each other instead of producing two copies of everything.

    The SARIF mapping is shared: on the Go side the Zimperium connector calls pkg/utils/sarif, the same
    utility other SARIF-reporting connectors use, parameterised by an identity prefix and a
    static/dynamic flag. This parser therefore extends the shared mixin rather than restating the
    mapping - the same way the shipped invicti parser extends netsparker. See
    dojo/tools/hiddenlayer/parser.py.

    What is Zimperium's own is the DECORATION: a SARIF document says nothing about which app or build it
    came from, so the connector adds the app name, the build version, the upload date and the platform
    afterwards. Those are what a mobile finding needs to be actionable, and a file has to supply them;
    see decorate().
    """

    vendor = "Zimperium"
    tool_prefix = "zimperium"
    # zScan analyses an uploaded build; nothing is exercised.
    is_static = True

    def __init__(self):
        # The app and assessment context for the file being parsed, read once in get_findings().
        self.context = {}

    def get_scan_types(self):
        # Byte-identical to the connector's ScanTypeName. Note it does NOT follow the
        # "<Vendor> - Connectors Import" pattern, so it cannot be derived - it has to be copied.
        return ["Zimperium zScan"]

    def get_label_for_scan_types(self, scan_type):
        return "Zimperium zScan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import a Zimperium zScan assessment SARIF report, optionally with the app and build "
            "context a SARIF document does not carry. Matches the scan type used by the Zimperium "
            "connector so file and API findings deduplicate - give the assessment id to deduplicate "
            "against connector findings."
        )

    def get_fields(self) -> list[str]:
        """
        Return the list of fields used in the Zimperium Parser.

        The SARIF fields come from the shared mapping; see SarifConnectorFindings. On top of those:
        - component_name / component_version: the app and its build version, from the export's context.
        - date: the date the build was uploaded.
        - tags: the SARIF tags, plus the app's platform.
        - unique_id_from_tool: "zimperium-<assessment id>-<rule id>-<file>:<line>".
        """
        return [
            "title",
            "severity",
            "description",
            "cvssv3_score",
            "cwe",
            "file_path",
            "line",
            "component_name",
            "component_version",
            "mitigation",
            "references",
            "date",
            "unique_id_from_tool",
            "vuln_id_from_tool",
            "unsaved_vulnerability_ids",
            "tags",
            "active",
            "false_p",
            "static_finding",
            "dynamic_finding",
        ]

    def get_dedupe_fields(self) -> list[str]:
        """
        Return the list of fields used for deduplication in the Zimperium Parser.

        Copied from the Zimperium block in the Pro connector settings, which pairs
        unique_id_from_tool_or_hash_code with these hash fields. The file path is in the hash because
        one rule firing on two files in an app bundle is two findings.
        """
        return ["title", "severity", "file_path", "vuln_id_from_tool"]

    def scope_id(self, data):
        """
        The ASSESSMENT id, which is one scan of one build.

        A downloaded SARIF report does not carry it, so without it the identities differ from the
        connector's and file findings will not deduplicate against synced ones.
        """
        context = self.assessment(data)
        return self.scope_from(data, ("assessment_id", "assessmentId", "id")) or self.scope_from(
            context, ("assessment_id", "assessmentId", "id"),
        )

    def prepare(self, data):
        """
        Read the app and build context before any finding is built.

        decorate() applies it to every finding as the shared mapping produces it, so it has to be in
        place first.
        """
        self.context = self.assessment(data)

    def assessment(self, data):
        """
        The app and assessment context: the app's name and platform, the build version and upload date.

        A file may state them at the top level or under an "assessment"/"app" object, which is how a
        saved export of the two calls looks.
        """
        if not isinstance(data, dict):
            return {}
        context = {}
        for key in ("assessment", "app", "context"):
            if isinstance(data.get(key), dict):
                context.update(data[key])
        for key in ("name", "appVersion", "buildNumber", "buildUploadedAt", "platform", "os",
                    "bundleIdentifier", "assessment_id", "assessmentId", "id"):
            if key in data and not isinstance(data.get(key), dict | list):
                context.setdefault(key, data[key])
        return context

    def decorate(self, finding, result):
        """
        Add the app and build context the SARIF document does not carry.

        A mobile finding is only actionable once you know which app and which build it is in - two
        builds of one app land in the same product, and without the version there is no telling them
        apart. Each field is only filled when the SARIF mapping left it empty, as the connector does.
        """
        context = self.context
        if not finding.component_name:
            finding.component_name = str(context.get("name") or "") or None
        if not finding.component_version:
            finding.component_version = str(context.get("appVersion") or "") or None
        if date := self.upload_date(context):
            finding.date = date
        if platform := str(context.get("platform") or ""):
            # Appended rather than merged, so the platform is last - the connector adds it after the
            # SARIF tags for the same reason.
            finding.unsaved_tags = [*(finding.unsaved_tags or []), platform]

    def upload_date(self, context):
        """
        The date the build was uploaded.

        The connector takes the first ten characters because it hands the API a string; this reads the
        same ten as a date, and skips one that is not a date rather than failing the import.
        """
        value = str(context.get("buildUploadedAt") or "").strip()
        if len(value) >= 10:
            with suppress(ValueError):
                return _date.fromisoformat(value[:10])
        return None
