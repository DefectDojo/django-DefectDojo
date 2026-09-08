import json

from dojo.models import Finding


class ThreatDragonParser:

    """
    Parser for OWASP Threat Dragon threat models.

    A Threat Dragon model holds diagrams whose cells carry the threats identified against
    them. Threats the modeller has already marked as mitigated are imported as mitigated
    Findings rather than dropped, so the model's history survives the import.
    """

    SEVERITY = {
        "critical": "Critical",
        "high": "High",
        "medium": "Medium",
        "low": "Low",
        "tbd": "Info",
    }

    def get_scan_types(self):
        return ["Threat Dragon Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import OWASP Threat Dragon threat models in JSON format."

    def get_findings(self, file, test):
        data = json.load(file)
        summary = data.get("summary") or {}
        model_title = summary.get("title")

        findings = []
        for diagram in (data.get("detail") or {}).get("diagrams", []) or []:
            diagram_title = diagram.get("title")
            for cell in self._cells(diagram):
                element = self._element_name(cell)
                findings.extend(
                    self._to_finding(threat, element, diagram_title, model_title, test)
                    for threat in cell.get("threats") or []
                )
        return findings

    def _cells(self, diagram):
        """Threat Dragon nests cells under diagramJson in v1 models and at the top level in v2."""
        diagram_json = diagram.get("diagramJson")
        if isinstance(diagram_json, dict):
            return diagram_json.get("cells") or []
        return diagram.get("cells") or []

    def _element_name(self, cell):
        """
        v1 models label a cell through its rendering attributes; v2 models carry the name
        as data. Fall back through both rather than assuming a schema version.
        """
        attrs_text = ((cell.get("attrs") or {}).get("text") or {}).get("text")
        if attrs_text:
            return attrs_text
        data_name = (cell.get("data") or {}).get("name")
        if data_name:
            return data_name
        return cell.get("label") or cell.get("name")

    def _to_finding(self, threat, element, diagram_title, model_title, test):
        title = threat.get("title")
        status = str(threat.get("status") or "").lower()

        description = []
        if threat.get("description"):
            description.append(threat["description"])
        if threat.get("type"):
            description.append(f"**Threat type:** {threat['type']}")
        if element:
            description.append(f"**Element:** {element}")
        if diagram_title:
            description.append(f"**Diagram:** {diagram_title}")
        if model_title:
            description.append(f"**Model:** {model_title}")
        if threat.get("status"):
            description.append(f"**Status:** {threat['status']}")

        finding = Finding(
            title=title,
            test=test,
            description="\n".join(description),
            severity=self.SEVERITY.get(str(threat.get("severity")).lower(), "Medium"),
            mitigation=threat.get("mitigation") or None,
            component_name=element,
            static_finding=True,
            dynamic_finding=False,
        )
        # A threat the modeller has already addressed is recorded as mitigated rather than
        # dropped, so the model's decisions are visible after import.
        if status == "mitigated":
            finding.is_mitigated = True
            finding.active = False
        else:
            finding.active = True
        return finding
