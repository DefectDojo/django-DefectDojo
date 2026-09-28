import json

from dojo.models import Finding


class NoirParser:

    """
    Parser for Noir JSON reports.

    Noir discovers the API attack surface of a codebase — every route, its method and its
    parameters — from source. It reports the endpoints it finds, not vulnerabilities, so each
    endpoint imports as informational attack-surface inventory. Noir does tag endpoints it
    considers security-relevant (an admin route, an endpoint taking a file path), and a tagged
    endpoint is raised above informational so it surfaces for review.
    """

    def get_scan_types(self):
        return ["Noir Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Noir attack-surface reports in JSON format, generated with 'noir -b <src> -f json'."

    def get_findings(self, file, test):
        data = json.load(file)
        return [self._to_finding(endpoint, test) for endpoint in data.get("endpoints", [])]

    def _to_finding(self, endpoint, test):
        url = endpoint.get("url")
        method = (endpoint.get("method") or "").upper()
        details = endpoint.get("details") or {}
        technology = details.get("technology")
        tags = endpoint.get("tags") or []
        params = endpoint.get("params") or []
        file_path, line = self._location(details)

        description = [f"**Endpoint:** {method} {url}"]
        if technology:
            description.append(f"**Technology:** {technology}")
        if endpoint.get("protocol"):
            description.append(f"**Protocol:** {endpoint['protocol']}")
        if params:
            rendered = ", ".join(
                f"{p.get('name')} ({p.get('param_type')})" for p in params if p.get("name")
            )
            description.append(f"**Parameters:** {rendered}")
        for tag in tags:
            name = tag.get("name") if isinstance(tag, dict) else tag
            reason = tag.get("description") if isinstance(tag, dict) else None
            description.append(f"**Tag `{name}`:** {reason}" if reason else f"**Tag:** {name}")
        if file_path:
            description.append(f"**Source:** {file_path}:{line}" if line else f"**Source:** {file_path}")

        return Finding(
            title=f"{method} {url}",
            test=test,
            # A plain endpoint is attack-surface inventory; a tagged one warrants a look.
            severity="Low" if tags else "Info",
            description="\n".join(description),
            file_path=file_path,
            line=line,
            vuln_id_from_tool=f"{method} {url}",
            static_finding=True,
            dynamic_finding=False,
        )

    def _location(self, details):
        for code_path in details.get("code_paths") or []:
            if code_path.get("path"):
                return code_path["path"], code_path.get("line")
        return None, None
