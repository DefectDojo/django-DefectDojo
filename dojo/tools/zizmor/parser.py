import json
import logging

from dojo.models import Finding

logger = logging.getLogger(__name__)

SEVERITY_MAPPING = {
    "Informational": "Info",
    "Low": "Low",
    "Medium": "Medium",
    "High": "High",
}


class ZizmorParser:

    """
    Parser for the JSON output of zizmor (https://docs.zizmor.sh/), a static analysis tool for GitHub Actions.

    zizmor emits a flat JSON array, one object per finding (`zizmor --format json <input>`).
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
        return [self._build_finding(item) for item in data]

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

    def _build_finding(self, item):
        ident = item["ident"]
        desc = item.get("desc") or ident
        url = item.get("url")
        determinations = item.get("determinations") or {}
        locations = item.get("locations") or []
        primary = self._primary_location(locations)

        file_path, repository = self._input_path(primary)
        line = self._line(primary)
        fixes = [fix.get("title") for fix in item.get("fixes") or [] if fix.get("title")]

        finding = Finding(
            title=desc[:1].upper() + desc[1:],
            severity=SEVERITY_MAPPING.get(determinations.get("severity"), "Info"),
            description=self._description(item, ident, desc, url, determinations, primary, locations),
            mitigation="\n".join(f"- {fix}" for fix in fixes) or None,
            references=url,
            vuln_id_from_tool=ident,
            file_path=file_path,
            line=line,
            static_finding=True,
            dynamic_finding=False,
            fix_available=bool(fixes),
        )
        if repository:
            # A remote audit ("zizmor owner/repo") can cover several repositories in one report.
            # The service field is part of every hash code, so findings in different repositories
            # that share a workflow path and line are not deduplicated against each other.
            finding.service = repository
        return finding

    def _primary_location(self, locations):
        for location in locations:
            if (location.get("symbolic") or {}).get("kind") == "Primary":
                return location
        return locations[0] if locations else {}

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

    def _description(self, item, ident, desc, url, determinations, primary, locations):
        lines = [
            f"**Audit:** {ident}: {desc}",
            f"**Severity:** {determinations.get('severity')}",
            f"**Confidence:** {determinations.get('confidence')}",
            f"**Persona:** {determinations.get('persona')}",
        ]
        if primary:
            lines.append(f"**Location:** {self._location_text(primary)}")
            annotation = (primary.get("symbolic") or {}).get("annotation")
            if annotation:
                lines.append(f"**Detail:** {annotation}")
            feature = (primary.get("concrete") or {}).get("feature")
            if feature:
                lines.extend(["**Code:**", "```", feature, "```"])
        related = [loc for loc in locations if loc is not primary and (loc.get("symbolic") or {}).get("kind") == "Related"]
        if related:
            lines.append("**Related locations:**")
            for location in related:
                annotation = (location.get("symbolic") or {}).get("annotation")
                suffix = f": {annotation}" if annotation else ""
                lines.append(f"- {self._location_text(location)}{suffix}")
        if item.get("ignored"):
            lines.append("**Ignored:** zizmor marks this finding as ignored (it was reported because of --no-ignores).")
        if url:
            lines.append(f"**Documentation and remediation:** {url}")
        return "\n".join(lines)
