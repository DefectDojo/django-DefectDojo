import json
import dateutil.parser

from dojo.models import Finding


class _PathNode(object):
    def __init__(self, file: str, line: str, column: str, _object: str, length: str, snippet: str):
        self.file = file
        self.line = line
        self.column = int(column)
        self._object = _object
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
            data.get("snippet")
        )


class _Path(object):
    def __init__(self, sink: _PathNode, source: _PathNode, state: int, paths: [_PathNode]):
        self.sink = sink
        self.source = source
        self.state = int(state)
        self.paths = paths


class CheckmarxCXFlowSastParser(object):
    def __init__(self):
        pass

    def get_scan_types(self):
        return ["CheckmarxCxFlow"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type  # no custom label for now

    def get_description_for_scan_types(self, scan_type):
        if scan_type == "CheckmarxCxFlow Scan":
            return "Simple Report. Aggregates vulnerabilities per categories, cwe, name, sinkFilename"
        else:
            return "Detailed Report. Import all vulnerabilities from checkmarx without aggregation"

    def get_findings(self, file, test):
        if file.name.strip().lower().endswith(".json"):
            return self._get_findings_json(file, test)
        else:
            return []

    def _get_findings_json(self, file, test):
        data = json.load(file)
        findings = []
        deepLink = data.get("deepLink")
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
                    paths=list([result[k] for k in path_keys])
                )

                map_paths[path.source.line] = path

            for detail_key in issue.get("details").keys():
                pass

                finding = Finding(
                    title=vulnerability.replace("_", " "),
                    cwe=int(cwe),
                    file_path=filename,
                    date=dateutil.parser.parse(scan_start_date),
                    static_finding=True,
                    unique_id_from_tool=similarity_id,
                )

            findings.append(finding)

        return findings

    def _get_findings_xml(self):
        pass

    def is_verify(self, status):
        pass

    def is_active(self, status):
        pass

    def is_mitigated(self, status):
        pass
