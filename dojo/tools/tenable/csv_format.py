import contextlib
import csv
import io
import logging
import re
import sys

from cpe import CPE
from cvss import CVSS3

from dojo.models import Endpoint, Finding, Test

LOGGER = logging.getLogger(__name__)


class TenableCSVParser:
    # Les méthodes get_fields, get_dedupe_fields et les conversions de sévérité
    # ne nécessitent pas de changement logique, elles restent donc telles quelles.
    # ... (le début de la classe reste identique)
    def get_fields(self) -> list[str]:
        return [
            "title", "description", "severity", "mitigation", "impact",
            "cvssv3", "component_name", "component_version",
        ]

    def get_dedupe_fields(self) -> list[str]:
        return ["title", "severity", "description"]

    def _validated_severity(self, severity):
        if severity not in Finding.SEVERITIES:
            severity = "Info"
        return severity

    def _int_severity_conversion(self, severity_value):
        severity = "Info"
        if severity_value == 4:
            severity = "Critical"
        elif severity_value == 3:
            severity = "High"
        elif severity_value == 2:
            severity = "Medium"
        elif severity_value == 1:
            severity = "Low"
        return self._validated_severity(severity)

    def _string_severity_conversion(self, severity_value):
        if severity_value is None or len(severity_value) == 0:
            return "Info"
        severity = severity_value.title()
        return self._validated_severity(severity)

    def _convert_severity(self, severity_value):
        if isinstance(severity_value, int):
            return self._int_severity_conversion(severity_value)
        if isinstance(severity_value, str):
            return self._string_severity_conversion(severity_value)
        return "Info"

    def _format_cve(self, val):
        if val is None or val == "":
            return None
        cve_match = re.findall(r"CVE-[0-9]+-[0-9]+", val.upper(), re.IGNORECASE)
        return cve_match or None

    def _format_cpe(self, val):
        if val is None or val == "":
            return None
        cpe_match = re.findall(r"cpe:/[^\n\ ]+", val)
        return cpe_match or None

    def detect_delimiter(self, content: str):
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")
        first_line = content.split("\n")[0]
        # Dans votre cas, les headers sont séparés par des tabulations '\t'
        if "\t" in first_line:
            return "\t"
        if ";" in first_line:
            return ";"
        return ","

    def get_findings(self, filename: str, test: Test):
        content = filename.read()
        delimiter = self.detect_delimiter(content)
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="ignore")

        csv.field_size_limit(int(sys.maxsize / 10))
        reader = csv.DictReader(io.StringIO(content), delimiter=delimiter)

        required_headers = ["definition.name", "asset.name", "Name", "Plugin Name"]
        if not any(h in reader.fieldnames for h in required_headers):
            msg = f"Fichier CSV invalide : en-tête requis manquant. Attendu un parmi {required_headers}"
            raise ValueError(msg)

        dupes = {}
        for row in reader:
            title = row.get("definition.name", row.get("Name", row.get("Plugin Name", row.get("asset.name"))))
            if not title:
                continue

            raw_severity = row.get("severity", row.get("Risk", row.get("Severity", "Info")))
            with contextlib.suppress(ValueError):
                int_severity = int(raw_severity)
                raw_severity = int_severity
            severity = self._convert_severity(raw_severity)

            description = row.get("definition.synopsis", row.get("Synopsis", "N/A"))
            
            severity_justification = f"Severity: {severity}\n"
            for field in [
                "definition.vpr.score", "definition.cvss3.base_score", "definition.cvss3.temporal_score",
                "definition.cvss2.base_score", "definition.cvss2.temporal_score", "definition.stig_severity",
                "definition.exploitability_ease", "VPR score", "Risk Factor", "STIG Severity"
            ]:
                if row.get(field):
                    severity_justification += f"{field}: {row.get(field)}\n"
            
            mitigation = row.get("definition.solution", row.get("Solution", "N/A"))
            impact = row.get("definition.description", row.get("Description", "N/A"))
            
            references = row.get("definition.see_also", row.get("See Also", ""))
            if row.get("definition.id"):
                references += f"\nTenable Plugin ID: {row.get('definition.id')}"
            if row.get("definition.plugin_version"):
                references += f"\nPlugin Version: {row.get('definition.plugin_version')}"
            if row.get("definition.vulnerability_published"):
                references += f"\nPublished: {row.get('definition.vulnerability_published')}"

            dupe_key = (
                severity, title,
                row.get("asset.host_name", row.get("Host", "No host")),
                str(row.get("port", row.get("Port", "No port"))),
                description,
            )

            exploit_info = str(row.get("definition.exploitability_ease", "")).strip().lower()
            known_exploited = "true" if exploit_info == "available" else "no"
            
            unique_id_from_tool = row.get("id")
            vuln_id_from_tool = row.get("definition.cve")            
            
            if dupe_key not in dupes:
                find = Finding(
                    title=title, test=test, description=description, severity=severity,
                    mitigation=mitigation, impact=impact, references=references,
                    severity_justification=severity_justification, known_exploited=known_exploited,
                    unique_id_from_tool=unique_id_from_tool, vuln_id_from_tool=vuln_id_from_tool,
                )

                cvss_vector = row.get("definition.cvss3.base_vector", row.get("CVSS V3 Vector", ""))
                if cvss_vector:
                    if not cvss_vector.startswith("CVSS:3"):
                        cvss_vector = "CVSS:3.1/" + cvss_vector
                    find.cvssv3 = CVSS3(cvss_vector).clean_vector(output_prefix=True)

                cvssv3_score = row.get("definition.cvss3.base_score", row.get("CVSSv3", ""))
                if cvssv3_score:
                    find.cvssv3_score = float(cvssv3_score)

                # ==================== BLOC MODIFIÉ ====================
                # On encapsule la logique CPE dans un try/except pour éviter de faire planter l'import
                detected_cpe = self._format_cpe(row.get("definition.cpe", row.get("CPE", "")))
                if detected_cpe:
                    cpe_string = detected_cpe[0]
                    try:
                        cpe_decoded = CPE(cpe_string)
                        find.component_name = cpe_decoded.get_product()[0] if cpe_decoded.get_product() else None
                        find.component_version = cpe_decoded.get_version()[0] if cpe_decoded.get_version() else None
                    except Exception as e:
                        # Si le CPE n'est pas valide, on enregistre un avertissement au lieu de planter.
                        LOGGER.warning(
                            f"Impossible de parser la chaîne CPE : '{cpe_string}'. Erreur : {e}. "
                            "Le nom et la version du composant ne seront pas ajoutés pour cette vulnérabilité."
                        )
                # ======================================================

                find.unsaved_endpoints = []
                find.unsaved_vulnerability_ids = []
                dupes[dupe_key] = find
            else:
                find = dupes[dupe_key]
            
            plugin_output = row.get("output", row.get("Plugin Output", ""))
            if plugin_output:
                find.description += f"\n\n--- Plugin Output ---\n{plugin_output}"

            detected_cve = self._format_cve(row.get("definition.cve", row.get("CVE", "")))
            if detected_cve:
                find.unsaved_vulnerability_ids.extend(detected_cve)

            host = row.get("asset.host_name", row.get("asset.display_ipv4_address", row.get("Host", row.get("IP Address", ""))))
            if not host:
                continue

            protocol = row.get("protocol", row.get("Protocol", "")).lower() or None
            port = str(row.get("port", row.get("Port", "")))
            if port in {"", "0"}:
                port = None

            endpoint = Endpoint(protocol=protocol, host=host, port=port)
            find.unsaved_endpoints.append(endpoint)

        return list(dupes.values())