import json
import logging
import re

from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY_MAPPING = {
    "Informational": "Info",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
}
SEVERITY_ORDER = ["Info", "Low", "Medium", "High"]

# Same scale as the Bandit parser: 1-2 is shown as Certain, 3-5 as Firm, 6+ as Tentative
CONFIDENCE_MAPPING = {
    "High": 2,
    "Medium": 3,
    "Low": 6,
}

# Some audits flag a whole job or workflow; its code is cut to this many lines in the description
MAX_CODE_LINES = 20

# A Regex fragment is the escaped expression text with \s+ for each run of whitespace. It is turned back
# into text by this fixed, linear rewrite; the pattern itself comes from the uploaded file and is never run.
REGEX_FRAGMENT_TOKEN = re.compile(r"\\s\+|\\(.)", re.DOTALL)


class ZizmorParser:

    """
    Parser for the JSON output of zizmor (https://docs.zizmor.sh/), a static analysis tool for GitHub Actions.

    zizmor emits a flat JSON array, one object per finding (`zizmor --format json <input>`). Some audits
    report one object per flagged expression, so several objects can share an audit, file and line; those
    become one finding with one occurrence per object.
    """

    def get_scan_types(self):
        return ["zizmor Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import the JSON output of zizmor (zizmor --format json), a static analysis tool for GitHub Actions workflows and actions."

    def get_findings(self, file, test):
        data = self._load_json(file)
        if not data:
            logger.info("zizmor report contains no findings")
            return []
        grouped = {}
        for item in data:
            occurrence = self._parse_occurrence(item)
            key = (occurrence["repository"], occurrence["ident"], occurrence["file_path"], occurrence["line"])
            grouped.setdefault(key, []).append(occurrence)
        return [self._build_finding(occurrences) for occurrences in grouped.values()]

    def _load_json(self, file):
        content = file.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8")
        try:
            data = json.loads(content)
        except json.JSONDecodeError as e:
            msg = "Invalid zizmor report: the file is not valid JSON. Generate it with 'zizmor --format json'."
            raise ValueError(msg) from e
        if not isinstance(data, list) or not all(isinstance(item, dict) and "ident" in item for item in data):
            msg = "Invalid zizmor report: expected a JSON array of findings as produced by 'zizmor --format json'."
            raise ValueError(msg)
        return data

    def _parse_occurrence(self, item):
        determinations = item.get("determinations") or {}
        locations = item.get("locations") or []
        primaries = [location for location in locations if (location.get("symbolic") or {}).get("kind") == "Primary"]
        if not primaries and locations:
            primaries = [locations[0]]
        first = primaries[0] if primaries else {}
        file_path, repository = self._input_path(first)
        return {
            "ident": item["ident"],
            "desc": item.get("desc") or item["ident"],
            "url": item.get("url"),
            "severity": determinations.get("severity"),
            "confidence": determinations.get("confidence"),
            "persona": determinations.get("persona"),
            "primaries": primaries,
            "related": [location for location in locations if (location.get("symbolic") or {}).get("kind") == "Related"],
            "fixes": [fix.get("title") for fix in item.get("fixes") or [] if fix.get("title")],
            "ignored": bool(item.get("ignored")),
            "file_path": file_path,
            "repository": repository,
            "line": self._line(first),
        }

    def _build_finding(self, occurrences):
        first = occurrences[0]
        severity = max(
            (SEVERITY_MAPPING.get(occurrence["severity"], "Info") for occurrence in occurrences),
            key=SEVERITY_ORDER.index,
        )
        confidences = [CONFIDENCE_MAPPING[o["confidence"]] for o in occurrences if o["confidence"] in CONFIDENCE_MAPPING]
        fixes = list(dict.fromkeys(fix for occurrence in occurrences for fix in occurrence["fixes"]))

        finding = Finding(
            title=first["desc"][:1].upper() + first["desc"][1:],
            severity=severity,
            description=self._description(occurrences),
            mitigation="\n".join(f"- {fix}" for fix in fixes) or None,
            references=first["url"],
            vuln_id_from_tool=first["ident"],
            file_path=first["file_path"],
            line=first["line"],
            nb_occurences=len(occurrences),
            static_finding=True,
            dynamic_finding=False,
            fix_available=bool(fixes),
        )
        if confidences:
            # the most confident occurrence
            finding.scanner_confidence = min(confidences)
        if first["repository"]:
            # A remote audit ("zizmor owner/repo") can cover several repositories in one report.
            # The service field is part of every hash code, so findings in different repositories
            # that share a workflow path and line are not deduplicated against each other.
            finding.service = first["repository"]
        return finding

    def _input_path(self, location):
        """Return (file path, repository slug) for a location. The slug is only set for remote inputs."""
        key = (location.get("symbolic") or {}).get("key") or {}
        if "Local" in key:
            path = (key["Local"] or {}).get("verbatim_path")
            if path and path.startswith("./"):
                path = path[2:]
            return path, None
        if "Remote" in key:
            remote = key["Remote"] or {}
            slug = remote.get("slug") or {}
            repository = "/".join(part for part in (slug.get("owner"), slug.get("repo")) if part) or None
            return remote.get("path"), repository
        return None, None

    def _line(self, location):
        start_point = (((location.get("concrete") or {}).get("location") or {}).get("start_point")) or {}
        row = start_point.get("row")
        # zizmor reports zero-based rows
        return row + 1 if isinstance(row, int) else None

    def _route(self, location):
        parts = []
        route = (((location.get("symbolic") or {}).get("route")) or {}).get("route") or []
        for component in route:
            if "Key" in component:
                parts.append(f".{component['Key']}" if parts else str(component["Key"]))
            elif "Index" in component:
                parts.append(f"[{component['Index']}]")
        return "".join(parts)

    def _flagged_expression(self, location):
        """Return the expression zizmor flags inside the location's code, such as github.event.pull_request.title."""
        feature_kind = (location.get("symbolic") or {}).get("feature_kind")
        if not isinstance(feature_kind, dict):
            return None
        fragment = (feature_kind.get("Subfeature") or {}).get("fragment") or {}
        if not isinstance(fragment, dict):
            return None
        raw = fragment.get("Raw")
        if isinstance(raw, str) and raw:
            return raw
        # zizmor uses a pattern when the expression contains whitespace, e.g. toJSON\(\s+secrets\s+\)
        pattern = fragment.get("Regex")
        if isinstance(pattern, str) and pattern:
            return REGEX_FRAGMENT_TOKEN.sub(lambda match: " " if match.group(1) is None else match.group(1), pattern)
        return None

    def _location_text(self, location):
        path, repository = self._input_path(location)
        text = path or "unknown file"
        if repository:
            text = f"{repository}: {text}"
        line = self._line(location)
        if line:
            text += f":{line}"
        route = self._route(location)
        if route:
            text += f" ({route})"
        return text

    def _code(self, feature):
        code_lines = feature.splitlines()
        code = "\n".join(code_lines[:MAX_CODE_LINES])
        if len(code_lines) > MAX_CODE_LINES:
            code += f"\n... ({len(code_lines) - MAX_CODE_LINES} more lines)"
        return code.replace("```", "\\`\\`\\`")

    def _inline_code(self, text):
        return f"`` {text} ``" if "`" in text else f"`{text}`"

    def _occurrence_lines(self, occurrence, shown_code=None):
        """
        Render one occurrence. When shown_code is a set, code already rendered for an earlier occurrence
        (results on one line usually share the enclosing step or run block) is not repeated.
        """
        lines = [
            f"**Severity:** {occurrence['severity']}",
            f"**Confidence:** {occurrence['confidence']}",
            f"**Persona:** {occurrence['persona']}",
        ]
        for location in occurrence["primaries"]:
            lines.append(f"**Location:** {self._location_text(location)}")
            annotation = (location.get("symbolic") or {}).get("annotation")
            if annotation:
                lines.append(f"**Detail:** {annotation}")
            expression = self._flagged_expression(location)
            if expression:
                lines.append(f"**Flagged expression:** {self._inline_code(expression)}")
            feature = (location.get("concrete") or {}).get("feature")
            if feature and shown_code is not None and feature in shown_code:
                lines.append("**Code:** as shown for an earlier occurrence")
            elif feature:
                lines.extend(["**Code:**", "```", self._code(feature), "```"])
                if shown_code is not None:
                    shown_code.add(feature)
        if occurrence["related"]:
            lines.append("**Related locations:**")
            for location in occurrence["related"]:
                annotation = (location.get("symbolic") or {}).get("annotation")
                suffix = f": {annotation}" if annotation else ""
                lines.append(f"- {self._location_text(location)}{suffix}")
        if occurrence["ignored"]:
            lines.append("**Ignored:** zizmor marks this finding as ignored (it was reported because of --no-ignores).")
        return lines

    def _description(self, occurrences):
        first = occurrences[0]
        lines = [f"**Audit:** {first['ident']}: {first['desc']}"]
        if len(occurrences) == 1:
            lines.extend(self._occurrence_lines(first))
        else:
            lines.append(f"**Occurrences:** {len(occurrences)} (zizmor reported this audit {len(occurrences)} times on this line)")
            # results that render identically (the same expression repeated on the line) are shown once, with a count
            identical = {}
            for occurrence in occurrences:
                identical.setdefault(tuple(self._occurrence_lines(occurrence)), []).append(occurrence)
            shown_code = set()
            for number, group in enumerate(identical.values(), start=1):
                header = f"**Occurrence {number}**"
                if len(group) > 1:
                    header += f" (reported {len(group)} times)"
                lines.extend(["", header])
                lines.extend(self._occurrence_lines(group[0], shown_code))
            lines.append("")
        if first["url"]:
            lines.append(f"**Documentation and remediation:** {first['url']}")
        return "\n".join(lines)
