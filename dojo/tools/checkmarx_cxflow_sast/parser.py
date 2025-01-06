import json
import logging

import dateutil.parser

from dojo.models import Finding

logger = logging.getLogger(__name__)


class _PathNode:
    def __init__(self, file: str, line: str, column: str, node_object: str, length: str, snippet: str):
        self.file = file
        self.line = line
        self.column = int(column)
        self.node_object = node_object
        self.length = int(length)
        self.snippet = snippet

    @classmethod
    def from_json_object(cls, data):
        return _PathNode(
            data.get("file"),
            data.get("line"),
            data.get("column"),
            data.get("object"),
            data.get("length"),
            data.get("snippet"),
        )


class _Path:
    def __init__(self, sink: _PathNode, source: _PathNode, state: str, paths: [_PathNode]):
        self.sink = sink
        self.source = source
        self.state = state
        self.paths = paths


class CheckmarxCXFlowSastParser:
    def __init__(self):
        pass

    def get_scan_types(self):
        return ["Checkmarx CxFlow SAST"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        return "Detailed Report. Import all vulnerabilities from checkmarx without aggregation"

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return self._get_findings_json(file, test)
        # TODO: support CxXML format
        logger.warning(f"Not supported file format ${file}")
        return []

    def _get_findings_json(self, file, test):
        data = json.load(file)
        findings = []
        additional_details = data.get("additionalDetails")
        scan_start_date = additional_details.get("scanStartDate")

        issues = data.get("xissues", [])

        for issue in issues:
            vulnerability = issue.get("vulnerability")
            status = issue.get("vulnerabilityStatus")
            cwe = issue.get("cwe")
            description = issue.get("description")
            language = issue.get("language")
            severity = issue.get("severity")
            link = issue.get("link")
            filename = issue.get("filename")
            similarity_id = issue.get("similarityId")

            issue_additional_details = issue.get("additionalDetails")
            categories = issue_additional_details.get("categories")
            results = issue_additional_details.get("results")

            map_paths = {}

            for result in results:
                # all path nodes exclude sink, source, state
                path_keys = sorted(filter(lambda k: isinstance(k, str) and k.isnumeric(), result.keys()))

                path = _Path(
                    sink=_PathNode.from_json_object(result.get("sink")),
                    source=_PathNode.from_json_object(result.get("source")),
                    state=result.get("state"),
                    paths=[result[k] for k in path_keys],
                )

                map_paths[str(path.source.line)] = path

            for detail_key in issue.get("details"):
                if detail_key not in map_paths:
                    logger.warning(f"{detail_key} not found in path, ignore")
                else:
                    detail = map_paths[detail_key]

                    finding_detail = f"**Category:** {categories}\n"
                    finding_detail += f"**Language:** {language}\n"
                    finding_detail += f"**Status:** {status}\n"
                    finding_detail += f"**Finding link:** [{link}]({link})\n"
                    finding_detail += f"**Description:** {description}\n"
                    finding_detail += f"**Source snippet:** `{detail.source.snippet if detail.source is not None else ''}`\n"
                    finding_detail += f"**Sink snippet:** `{detail.sink.snippet if detail.sink is not None else ''}`\n"

                    finding = Finding(
                        title=vulnerability.replace("_", " ") + " " + detail.sink.file.split("/")[
                            -1] if detail.sink is not None else "",
                        cwe=int(cwe),
                        date=dateutil.parser.parse(scan_start_date),
                        static_finding=True,
                        test=test,
                        sast_source_object=detail.source.node_object if detail.source is not None else None,
                        sast_sink_object=detail.sink.node_object if detail.sink is not None else None,
                        sast_source_file_path=detail.source.file if detail.source is not None else None,
                        sast_source_line=detail.source.line if detail.source is not None else None,
                        vuln_id_from_tool=similarity_id,
                        severity=severity,
                        file_path=filename,
                        line=detail.sink.line,
                        false_p=issue.get("details")[detail_key].get("falsePositive") or self.is_not_exploitable(
                            detail.state),
                        description=finding_detail,
                        verified=self.is_verify(detail.state),
                        active=self.is_active(detail.state),
                    )

                    findings.append(finding)

        return findings

    def is_verify(self, state):
        # Confirmed, urgent
        verifiedStates = ["2", "3"]
        return state in verifiedStates

    def is_active(self, state):
        # To verify, Confirmed, Urgent, Proposed not exploitable
        activeStates = ["0", "2", "3", "4"]
        return state in activeStates

    def is_not_exploitable(self, state):
        return state == "1"
