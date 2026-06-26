import json
import logging
from itertools import groupby, islice

from django.conf import settings

from dojo.models import Finding
from dojo.tools.locations import LocationData

logger = logging.getLogger(__name__)

SEVERITY = "Info"


def load_govulncheck_stream(scan_file):
    """
    Load govulncheck output that may be a single JSON document or a stream of concatenated JSON objects.

    Returns the parsed object (dict for the old format, list for the new streaming format).
    Raises ValueError on unparseable input.
    """
    try:
        return json.load(scan_file)
    except json.JSONDecodeError:
        scan_file.seek(0)
        data = []
        buf = ""
        for line in scan_file:
            if not line.strip():
                continue
            buf += line.decode("utf-8") if isinstance(line, bytes) else line
            try:
                data.append(json.loads(buf))
                buf = ""
            except json.JSONDecodeError:
                continue
        if not data:
            msg = "Invalid JSON format"
            raise ValueError(msg)
        return data


class GovulncheckParser:
    def get_scan_types(self):
        return ["Govulncheck Scanner"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Govulncheck Scanner findings in JSON format."

    @staticmethod
    def get_location(data, node):
        while (
            data["Calls"]["Functions"][str(node)]["CallSites"][0]["Parent"]
            != 1
        ):
            node = data["Calls"]["Functions"][str(node)]["CallSites"][0][
                "Parent"
            ]
        return [
            f"{x['Pos']['Filename']}:{x['Pos']['Line']}:{x['Pos']['Column']}"
            for x in data["Calls"]["Functions"][str(node)]["CallSites"]
        ]

    @staticmethod
    def get_version(data, node):
        return data["Requires"]["Modules"][str(node)]["Version"]

    @staticmethod
    def get_fix_info(affected_ranges):
        for r in affected_ranges:
            for event in r.get("events", []):
                if "fixed" in event:
                    return True, event["fixed"]
        return False, ""

    @staticmethod
    def get_introduced_version(affected_ranges):
        for r in affected_ranges:
            for event in r.get("events", []):
                if "introduced" in event:
                    return event["introduced"]
        return ""

    def get_finding_trace_info(self, data, osv_id):
        # Browse the findings to look for matching OSV-id. If the OSV-id is matching, extract traces.
        trace_info_strs = []
        for elem in data:
            if "finding" in elem:
                finding = elem["finding"]
                if finding.get("osv") == osv_id:
                    trace_info = finding.get("trace", [])
                    for trace in trace_info:
                        module = trace.get("module", "Unknown module")
                        version = trace.get("version", "Unknown version")
                        package = trace.get("module", "Unknown package")
                        function = trace.get("function", "Unknown function")
                        filename = trace.get("position", {}).get("filename", "Unknown filename")
                        line = trace.get("position", {}).get("line", "Unknown line")
                        trace_info_str = f"\tModule: {module}, Version: {version}, Package: {package}, Function: {function}, File: {filename}, Line: {line}"
                        trace_info_strs.append(trace_info_str)
        return "\n".join(trace_info_strs)

    def get_affected_version(self, data, osv_id):
        # Browse the findings to look for matching OSV-id. If the OSV-id is matching, extract the first affected version.
        for elem in data:
            if "finding" in elem:
                finding = elem["finding"]
                if finding.get("osv") == osv_id:
                    trace_info = finding.get("trace", [])
                    for trace in trace_info:
                        if "version" in trace:
                            return trace.get("version")
        return ""

    def get_findings(self, scan_file, test):
        findings = []
        try:
            try:
                data = json.load(scan_file)
            except json.JSONDecodeError:
                scan_file.seek(0)
                data = []
                buf = ""
                for line in scan_file:
                    if not line.strip():
                        continue
                    buf += line.decode("utf-8") if isinstance(line, bytes) else line
                    try:
                        data.append(json.loads(buf))
                        buf = ""
                    except json.JSONDecodeError:
                        continue
                if not data:
                    raise ValueError
        except Exception:
            msg = "Invalid JSON format"
            raise ValueError(msg)
        else:
            if isinstance(data, dict):
                if data["Vulns"]:
                    # Parsing for old govulncheck output format
                    list_vulns = data["Vulns"]
                    for cve, elems in groupby(
                        list_vulns, key=lambda vuln: vuln["OSV"]["aliases"][0],
                    ):
                        elem_values = list(elems)
                        first_elem = list(islice(elem_values, 1))
                        d = {
                            "cve": cve,
                            "severity": SEVERITY,
                            "title": first_elem[0]["OSV"]["id"],
                            "component_name": first_elem[0]["OSV"]["affected"][0][
                                "package"
                            ]["name"],
                            "component_version": self.get_version(
                                data, first_elem[0]["RequireSink"],
                            ),
                        }
                        d["references"] = first_elem[0]["OSV"]["references"][0][
                            "url"
                        ]
                        d["url"] = first_elem[0]["OSV"]["affected"][0][
                            "database_specific"
                        ]["url"]
                        d["unique_id_from_tool"] = first_elem[0]["OSV"]["id"]
                        vuln_methods = set(
                            first_elem[0]["OSV"]["affected"][0][
                                "ecosystem_specific"
                            ]["imports"][0]["symbols"],
                        )
                        impact = set(
                            self.get_location(data, first_elem[0]["CallSink"]),
                        )
                        for elem in elem_values:
                            impact.update(
                                self.get_location(data, elem["CallSink"]),
                            )
                            vuln_methods.update(
                                elem["OSV"]["affected"][0]["ecosystem_specific"][
                                    "imports"
                                ][0]["symbols"],
                            )
                        d["impact"] = "; ".join(impact) if impact else None
                        d[
                            "description"
                        ] = f"Vulnerable functions: {'; '.join(vuln_methods)}"
                        finding = Finding(**d)
                        if settings.V3_FEATURE_LOCATIONS and d["component_name"]:
                            finding.unsaved_locations.append(
                                LocationData.dependency(purl_type="golang", name=d["component_name"], version=d["component_version"]),
                            )
                        findings.append(finding)
            elif isinstance(data, list):
                # Parsing for new govulncheck output format
                for elem in data:
                    if "osv" in elem:
                        cve = elem["osv"]["aliases"][0]
                        osv_data = elem["osv"]
                        affected_package = osv_data["affected"][0]["package"]
                        affected_ranges = osv_data["affected"][0]["ranges"]
                        affected_ecosystem = affected_package.get("ecosystem", "Unknown")
                        impact = osv_data.get("details", "Unknown")
                        formatted_ranges = []
                        summary = osv_data.get("summary", "Unknown")
                        component_name = affected_package["name"]
                        osv_id = osv_data["id"]

                        for r in affected_ranges:
                            events = r["events"]
                            event_pairs = []
                            for i in range(0, len(events), 2):
                                # Events come in pairs: introduced, then fixed
                                introduced = events[i].get("introduced", "Unknown")
                                fixed = events[i + 1].get("fixed", "Unknown") if i + 1 < len(events) else "Unknown"
                                event_pairs.append(f"\n\t\tIntroduced in {introduced}, fixed in {fixed}")
                            formatted_ranges.append(f"type {r['type']}: {'. '.join(event_pairs)}")
                        range_info = "\n ".join(formatted_ranges)

                        vuln_functions = ", ".join(
                            set(osv_data["affected"][0].get("ecosystem_specific", {}).get("imports", [{}])[0].get("symbols", [])),
                        )

                        description = (
                            f"**Summary:** {summary}\n"
                            f"**Vulnerable functions:** {vuln_functions}\n"
                            f"**Affected Ecosystem:** {affected_ecosystem}\n"
                            f"**Affected Versions:** {range_info}\n"
                            f"**Vulnerable Package:** {affected_package['name']}\n"
                            f"**Traces found :**\n{self.get_finding_trace_info(data, osv_data['id'])}"
                        )

                        references = [f"{ref['type']}: {ref['url']}" for ref in osv_data.get("references", [])]
                        db_specific_url = osv_data["database_specific"].get("url", "Unknown")
                        if db_specific_url:
                            references.append(f"Database: {db_specific_url}")
                        references = "\n".join(references)

                        ecosystem_specific = osv_data["affected"][0].get("ecosystem_specific", {})
                        imports = ecosystem_specific.get("imports", [{}])
                        path = imports[0].get("path", "") if imports else ""
                        if path:
                            title = f"{osv_data['id']} - {affected_package['name']} - {path}"
                        else:
                            title = f"{osv_data['id']} - {affected_package['name']}"

                        fix_available, fix_version = self.get_fix_info(affected_ranges)

                        affected_version = (
                            self.get_affected_version(data, osv_data["id"])
                            or self.get_introduced_version(affected_ranges)
                        )
                        severity = elem["osv"].get("severity", SEVERITY)

                        d = {
                            "cve": cve,
                            "severity": severity,
                            "title": title,
                            "component_name": component_name,
                            "component_version": affected_version,
                            "description": description,
                            "impact": impact,
                            "references": references,
                            "fix_available": fix_available,
                            "fix_version": fix_version,
                            "file_path": path,
                            "url": db_specific_url,
                            "unique_id_from_tool": osv_id,
                        }

                        finding = Finding(**d)
                        if settings.V3_FEATURE_LOCATIONS and component_name:
                            finding.unsaved_locations.append(
                                LocationData.dependency(purl_type="golang", name=component_name, version=affected_version, file_path=path),
                            )
                        findings.append(finding)
            return findings


class GovulncheckParserV2:

    """
    Govulncheck parser v2.

    Iterates the ``finding`` records of the streaming JSON output instead of the
    ``osv`` advisory definitions. This:

    * Drops advisories that are present in the vulnerability database stream but
      do not actually apply to the scanned code (the old parser imported these,
      inflating the finding count).
    * Derives a severity from govulncheck's reachability level, since the Go
      vulnerability database does not provide CVSS scores:
        - ``symbol``  (vulnerable symbol is called)   -> High
        - ``package`` (vulnerable package imported)   -> Low
        - ``module``  (vulnerable module required)    -> Info
    * Emits one finding per (osv, module) pair so multi-module advisories map to
      the correct vulnerable components.
    """

    # govulncheck reachability level -> DefectDojo severity.
    # Kept separate per level so each reachability tier is distinguishable.
    LEVEL_SEVERITY = {
        "symbol": "High",
        "package": "Low",
        "module": "Info",
    }
    LEVEL_RANK = {"module": 1, "package": 2, "symbol": 3}

    def get_scan_types(self):
        return ["Govulncheck Scanner V2"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import Govulncheck Scanner findings in JSON format. V2 derives "
            "severity from reachability and maps findings to components."
        )

    @staticmethod
    def get_level(trace_entry):
        if "function" in trace_entry:
            return "symbol"
        if "package" in trace_entry:
            return "package"
        return "module"

    @staticmethod
    def format_trace(trace):
        # trace[0] is the vulnerable sink, the last entry is the entry point in user code.
        lines = []
        for entry in trace:
            module = entry.get("module", "Unknown module")
            version = entry.get("version", "")
            package = entry.get("package", "")
            function = entry.get("function", "")
            pos = entry.get("position", {})
            location = ""
            if pos:
                location = f"{pos.get('filename', '')}:{pos.get('line', '')}:{pos.get('column', '')}"
            symbol = ".".join(p for p in (package, function) if p)
            parts = [f"Module: {module}@{version}" if version else f"Module: {module}"]
            if symbol:
                parts.append(f"Symbol: {symbol}")
            if location:
                parts.append(f"Location: {location}")
            lines.append("\t" + ", ".join(parts))
        return "\n".join(lines)

    def get_findings(self, scan_file, test):
        data = load_govulncheck_stream(scan_file)
        # The v2 parser only targets the new streaming format (a list of objects).
        if not isinstance(data, list):
            return []

        osv_defs = {
            elem["osv"]["id"]: elem["osv"]
            for elem in data
            if isinstance(elem, dict) and "osv" in elem
        }

        # Group findings by (osv_id, module).
        groups = {}
        for elem in data:
            if not (isinstance(elem, dict) and "finding" in elem):
                continue
            finding = elem["finding"]
            osv_id = finding.get("osv")
            trace = finding.get("trace") or [{}]
            sink = trace[0]
            module = sink.get("module", "Unknown")
            key = (osv_id, module)
            level = self.get_level(sink)
            group = groups.setdefault(key, {
                "osv_id": osv_id,
                "module": module,
                "version": sink.get("version", ""),
                "package": sink.get("package", ""),
                "level": level,
                "fixed_version": finding.get("fixed_version", ""),
                "traces": [],
            })
            # Keep the highest reachability level seen for this component.
            if self.LEVEL_RANK[level] > self.LEVEL_RANK[group["level"]]:
                group["level"] = level
            if not group["fixed_version"]:
                group["fixed_version"] = finding.get("fixed_version", "")
            if len(trace) > 1 or "function" in sink:
                group["traces"].append(trace)

        findings = []
        for group in groups.values():
            osv = osv_defs.get(group["osv_id"], {})
            osv_id = group["osv_id"]
            module = group["module"]
            version = group["version"]
            level = group["level"]
            fixed_version = group["fixed_version"]

            aliases = osv.get("aliases") or []
            cve = aliases[0] if aliases else None
            summary = osv.get("summary", "")
            details = osv.get("details", "")
            db_specific = osv.get("database_specific", {}) or {}
            url = db_specific.get("url", "")

            title = f"{osv_id} - {module}"

            description_parts = [
                f"**Summary:** {summary or 'Unknown'}",
                f"**Vulnerable module:** {module}@{version}" if version else f"**Vulnerable module:** {module}",
                f"**Reachability:** {level} ({self.LEVEL_SEVERITY[level]} severity)",
            ]
            if details:
                description_parts.append(f"**Details:** {details}")
            if group["traces"]:
                trace_blocks = "\n".join(self.format_trace(t) for t in group["traces"])
                description_parts.append(f"**Traces:**\n{trace_blocks}")
            description = "\n".join(description_parts)

            references = [
                f"{ref.get('type', 'WEB')}: {ref['url']}"
                for ref in osv.get("references", [])
                if ref.get("url")
            ]
            if url:
                references.append(f"Database: {url}")

            d = {
                "title": title,
                "severity": self.LEVEL_SEVERITY[level],
                "cve": cve,
                "component_name": module,
                "component_version": version,
                "description": description,
                "references": "\n".join(references),
                "fix_available": bool(fixed_version),
                "fix_version": fixed_version,
                "url": url,
                "unique_id_from_tool": f"{osv_id}:{module}",
            }
            finding = Finding(**d)
            if settings.V3_FEATURE_LOCATIONS and module:
                finding.unsaved_locations.append(
                    LocationData.dependency(purl_type="golang", name=module, version=version),
                )
            findings.append(finding)
        return findings
