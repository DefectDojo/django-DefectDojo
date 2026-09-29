import contextlib
import json
from urllib.parse import urlparse

from dojo.location.feature import locations_enabled
from dojo.models import Endpoint, Finding
from dojo.tools.locations import LocationData


class DalfoxParser:

    """
    Parser for Dalfox, an XSS scanner.

    ``dalfox --format json`` writes a JSON array of results. Each result records the parameter
    Dalfox injected into, the payload it used, the proof of concept URL and the evidence it saw
    reflected back.

    Two quirks of the real output are handled here. Dalfox appends an empty object to the end of
    the array, which is not a result and is skipped. And Dalfox reports the same parameter many
    times with different payloads, because each payload is a separate attempt; those are all kept,
    and deduplication folds them together on the parameter and the endpoint afterwards.
    """

    # Dalfox's own severity strings, which it sets from the result type.
    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "info": "Info",
    }

    # Dalfox result types: V is a verified injection (it ran the payload in a browser and saw it
    # execute), R is a reflected payload it did not verify, G is a pattern it grepped for.
    TYPE_LABELS = {
        "V": "Verified — payload executed",
        "R": "Reflected — payload echoed but not verified",
        "G": "Grep — matched a configured pattern",
    }

    def get_scan_types(self):
        return ["Dalfox Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Dalfox reports in JSON format, generated with 'dalfox url <target> --format json'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for result in data if isinstance(data, list) else [data]:
            # Dalfox terminates its array with an empty object.
            if not result:
                continue
            findings.append(self._to_finding(result, test))
        return findings

    def _to_finding(self, result, test):
        result_type = result.get("type") or ""
        parameter = result.get("param") or ""
        inject_type = result.get("inject_type") or ""
        poc_url = result.get("data") or ""

        title = result.get("message_str") or f"XSS in parameter {parameter}"
        if parameter:
            title = f"{parameter}: {title}"

        description = []
        if result.get("message_str"):
            description.append(result["message_str"])
        if result_type:
            description.append(f"**Result type:** {result_type} ({self.TYPE_LABELS.get(result_type, 'unknown')})")
        if parameter:
            description.append(f"**Parameter:** {parameter}")
        if result.get("method"):
            description.append(f"**Method:** {result['method']}")
        if inject_type:
            description.append(f"**Injection point:** {inject_type}")
        if result.get("poc_type"):
            description.append(f"**Proof of concept type:** {result['poc_type']}")
        if result.get("payload"):
            description.append(f"**Payload:**\n```\n{result['payload']}\n```")
        if result.get("evidence"):
            description.append(f"**Evidence:**\n```\n{result['evidence']}\n```")
        if poc_url:
            description.append(f"**Proof of concept:**\n```\n{poc_url}\n```")
        if result.get("message_id") is not None:
            description.append(f"**Dalfox message id:** {result['message_id']}")

        finding = Finding(
            title=title,
            test=test,
            description=(description and "\n".join(description)) or title,
            severity=self.SEVERITY.get((result.get("severity") or "").lower(), "Medium"),
            param=parameter or None,
            # The parameter is also the component: it is the injectable thing being reported, and
            # it is what deduplication needs to tell two parameters on one URL apart.
            component_name=parameter or None,
            payload=result.get("payload") or None,
            vuln_id_from_tool=f"{result_type}-{inject_type}" if result_type or inject_type else None,
            static_finding=False,
            dynamic_finding=True,
        )

        cwe = result.get("cwe")
        if isinstance(cwe, str) and cwe.upper().startswith("CWE-"):
            with contextlib.suppress(IndexError, ValueError):
                finding.cwe = int(cwe.split("-", 1)[1])

        self._attach_location(finding, poc_url)
        return finding

    @staticmethod
    def _attach_location(finding, poc_url):
        """
        Turn the proof of concept URL into a location (or, pre-Locations, an endpoint).

        The query string is deliberately dropped: it holds the payload, which differs on every
        attempt, so keeping it would make every payload a separate location for what is one
        injectable parameter. The payload itself is on the Finding.
        """
        if not poc_url:
            return
        parsed = urlparse(poc_url)
        if not parsed.hostname:
            return
        if locations_enabled():
            finding.unsaved_locations.append(LocationData.url(
                host=parsed.hostname,
                port=parsed.port,
                protocol=parsed.scheme or "",
                path=parsed.path.lstrip("/"),
            ))
        else:
            # TODO: Delete this after the move to Locations
            finding.unsaved_endpoints.append(Endpoint(
                host=parsed.hostname,
                port=parsed.port,
                protocol=parsed.scheme or None,
                path=parsed.path.lstrip("/") or None,
            ))
