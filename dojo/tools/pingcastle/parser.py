
import contextlib
import datetime
import re

from defusedxml.ElementTree import parse
from django.conf import settings

from dojo.models import Endpoint, Finding
from dojo.url.models import URL


class PingCastleParser:

    CVE_REGEX = re.compile(r"(CVE-\d{4}-\d{4,7})", re.IGNORECASE)

    _SEVERITY_ORDER = ["Info", "Low", "Medium", "High", "Critical"]

    def get_scan_types(self):
        return ["PingCastle"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "PingCastle XML export"

    def get_findings(self, file, test):
        try:
            tree = parse(file)
            root = tree.getroot()
        except Exception as e:
            exception = f"Invalid PingCastle XML format: {e}"
            raise ValueError(exception)
        dupes = {}
        report_date = self._parse_datetime(root.findtext("GenerationDate"))
        domain_fqdn = root.findtext("DomainFQDN") or ""
        dc_infos, dc_locations = self._collect_domain_controllers(root)
        findings = []
        for rr in root.findall("RiskRules/HealthcheckRiskRule"):
            points = self._safe_int(rr.findtext("Points"))
            category = rr.findtext("Category") or ""
            model = rr.findtext("Model") or ""
            risk_id = rr.findtext("RiskId") or ""
            rationale = rr.findtext("Rationale") or ""
            severity = self._map_points_to_severity(points)
            severity = self._apply_contextual_bump(
                severity=severity,
                category=category,
                model=model,
                risk_id=risk_id,
                rationale=rationale,
            )
            if not severity or severity not in self._SEVERITY_ORDER:
                severity = "Info"
            title = f"[PingCastle] {risk_id} ({category}/{model})"
            description = self._compose_risk_rule_description(
                domain_fqdn=domain_fqdn,
                risk_id=risk_id,
                points=points,
                category=category,
                model=model,
                rationale=rationale,
                dc_infos=dc_infos,
                root=root,
            )
            finding = Finding(
                title=title,
                test=test,
                description=description,
                severity=severity,
                mitigation="Review and remediate according to PingCastle recommendations.",
                impact="Risk identified by PingCastle HealthCheck.",
                vuln_id_from_tool=risk_id,
            )
            if report_date:
                finding.date = report_date
            cves = list(self.CVE_REGEX.findall(rationale or ""))
            if cves:
                finding.unsaved_vulnerability_ids = cves

            if settings.V3_FEATURE_LOCATIONS:
                if self._is_dc_specific_risk(risk_id, model, rationale):
                    finding.unsaved_locations.extend(dc_locations)
                elif domain_fqdn:
                    finding.unsaved_locations.append(URL(host=domain_fqdn))
            # TODO: Delete this after the move to Locations
            elif self._is_dc_specific_risk(risk_id, model, rationale):
                finding.unsaved_endpoints.extend(dc_locations)
            elif domain_fqdn:
                finding.unsaved_endpoints.append(Endpoint(host=domain_fqdn))

            if risk_id == "A-DC-Coerce":
                self._enrich_coerce_with_rpc_interfaces(finding, dc_infos)
            if risk_id == "A-DC-Spooler":
                self._enrich_spooler_status(finding, dc_infos)
            if risk_id == "A-MinPwdLen":
                self._enrich_password_policy(finding, root)
            dupe_key = risk_id
            if dupe_key in dupes:
                existing = dupes[dupe_key]
                existing.description += "\n\n-----\n\n" + finding.description
                if settings.V3_FEATURE_LOCATIONS:
                    existing.unsaved_locations.extend(finding.unsaved_locations)
                else:
                    # TODO: Delete this after the move to Locations
                    existing.unsaved_endpoints.extend(finding.unsaved_endpoints)
            else:
                dupes[dupe_key] = finding
        findings.extend(list(dupes.values()))
        return findings

    def _compose_risk_rule_description(
        self,
        domain_fqdn,
        risk_id,
        points,
        category,
        model,
        rationale,
        dc_infos,
        root,
    ):
        lines = []
        lines.append("### PingCastle Risk Rule")  # noqa: FURB113
        lines.append(f"**Domain**: `{domain_fqdn}`")
        lines.append(f"**RiskId**: `{risk_id}`")
        lines.append(f"**Category/Model**: `{category}` / `{model}`")
        lines.append(f"**Points**: `{points}`")
        if rationale:
            lines.append(f"**Rationale**: {rationale}")
        if risk_id.startswith("A-DC-") or "DomainControllers" in root.tag:
            if dc_infos:
                lines.append("\n#### Domain Controllers")
                for dc in dc_infos:
                    ips = ", ".join(dc.get("ips", []))
                    lines.append(
                        f"- **{dc['name']}** (OS: {dc.get('os', '?')}, IPs: {ips}, "
                        f"SpoolerRemote: {dc.get('remote_spooler', 'false')})",
                    )
        return "\n".join(lines)

    def _collect_domain_controllers(self, root):
        dc_infos = []
        locations = []
        for dc in root.findall("DomainControllers/HealthcheckDomainController"):
            name = dc.findtext("DCName") or ""
            os = dc.findtext("OperatingSystem") or ""
            remote_spooler = dc.findtext("RemoteSpoolerDetected") or "false"
            ip_elems = dc.findall("IP/string")
            ips = [ip_elem.text for ip_elem in ip_elems if ip_elem is not None and ip_elem.text]
            dc_info = {
                "name": name,
                "os": os,
                "remote_spooler": remote_spooler.lower() == "true",
                "ips": ips,
                "rpc_interfaces": [],
            }
            for rpc in dc.findall("RPCInterfacesOpen/HealthcheckDCRPCInterface"):
                dc_info["rpc_interfaces"].append({
                    "ip": rpc.attrib.get("IP", ""),
                    "interface": rpc.attrib.get("Interface", ""),
                    "opnum": rpc.attrib.get("OpNum", ""),
                    "function": rpc.attrib.get("Function", ""),
                })
            dc_infos.append(dc_info)
            if settings.V3_FEATURE_LOCATIONS:
                if name:
                    locations.append(URL(host=name))
                locations.extend(URL(host=ip) for ip in ips)
            else:
                # TODO: Delete this after the move to Locations
                if name:
                    locations.append(Endpoint(host=name))
                locations.extend(Endpoint(host=ip) for ip in ips)
        return dc_infos, locations

    def _enrich_coerce_with_rpc_interfaces(self, finding, dc_infos):
        added_any = False
        for dc in dc_infos:
            if dc.get("rpc_interfaces"):
                if not added_any:
                    finding.description += "\n\n#### RPC Interfaces (potential coercion surface)\n"
                    added_any = True
                finding.description += f"\n**{dc['name']}**:\n"
                for ri in dc["rpc_interfaces"]:
                    finding.description += (
                        f"- IP: `{ri['ip']}` | Interface: `{ri['interface']}` | "
                        f"OpNum: `{ri['opnum']}` | Function: `{ri['function']}`\n"
                    )

    def _enrich_spooler_status(self, finding, dc_infos):
        any_remote_spooler = any(dc.get("remote_spooler") for dc in dc_infos)
        finding.description += (
            f"\n\n**Remote spooler exposure detected**: `{any_remote_spooler}`"
        )

    def _enrich_password_policy(self, finding, root):
        min_len = None
        complexity = None
        for prop in root.findall("GPPPasswordPolicy/GPPSecurityPolicy/Properties/GPPSecurityPolicyProperty"):
            key = (prop.findtext("Property") or "").strip()
            val = (prop.findtext("Value") or "").strip()
            if key == "MinimumPasswordLength":
                min_len = val
            elif key == "PasswordComplexity":
                complexity = val
        if min_len is not None or complexity is not None:
            finding.description += "\n\n#### Observed Password Policy from GPO\n"
            if min_len is not None:
                finding.description += f"- MinimumPasswordLength: `{min_len}`\n"
            if complexity is not None:
                friendly = {"0": "disabled", "1": "enabled"}.get(complexity, complexity)
                finding.description += f"- PasswordComplexity: `{friendly}`\n"

    @staticmethod
    def _parse_datetime(text):
        if not text:
            return None
        with contextlib.suppress(ValueError):
            return datetime.datetime.fromisoformat(text)
        return None

    @staticmethod
    def _safe_int(text):
        try:
            return int(text)
        except (TypeError, ValueError):
            return 0

    @staticmethod
    def _map_points_to_severity(points):
        if points <= 0:
            return "Info"
        if points <= 5:
            return "Low"
        if points <= 10:
            return "Medium"
        if points <= 15:
            return "High"
        return "Critical"

    @staticmethod
    def _is_dc_specific_risk(risk_id: str, model: str = "", rationale: str = "") -> bool:
        """
        Best effort classification: return True if the risk targets Domain Controllers specifically.
        Signals:
        - RiskId prefixes for DC: "A-DC-" (anomalies on DC), "S-DC-" (stale/DC subnet), and known IDs.
        - Model contains DC-specific notions (e.g., "Audit" with RiskId A-AuditDC).
        - Rationale text mentions DC count/context ("from X DC", "on domain controllers").
        """
        rid = (risk_id or "").strip()
        mod = (model or "").strip()
        rat = (rationale or "").strip().lower()
        dc_prefixes = ("A-DC-", "S-DC-")
        if rid.startswith(dc_prefixes):
            return True
        dc_specific_ids = {
            "A-DC-Spooler",
            "A-DC-Coerce",
            "A-AuditDC",
            "S-DC-SubnetMissing",
        }
        if rid in dc_specific_ids:
            return True
        if mod == "Audit" and rid.endswith("DC"):
            return True
        dc_markers = (
            " from ",
            " dc",
            " dcs",
            " domain controller",
            " domain controllers",
        )
        return bool(any(marker in rat for marker in dc_markers))

    def _apply_contextual_bump(self, severity: str, category: str = "", model: str = "",
                               risk_id: str = "", rationale: str = "") -> str:
        """
        Minimal additive logic on top of points-based severity:
        - If a CVE is mentioned -> bump by 1 level (at least Low).
          If rationale indicates missing/not enabled mitigation -> ensure at least Medium.
        - If DC-specific -> bump by 1 level.
        - If category is 'Exposure' -> bump by 1 level.
        """
        if not severity or severity not in self._SEVERITY_ORDER:
            severity = "Info"
        idx = self._SEVERITY_ORDER.index(severity)
        rat = (rationale or "").lower()
        cat = (category or "").strip().lower()

        if self.CVE_REGEX.search(rationale or ""):
            idx = min(idx + 1, len(self._SEVERITY_ORDER) - 1)
            mitigation_markers = ("mitigation", "not set", "disabled", "missing", "not enabled", "enable")
            if any(m in rat for m in mitigation_markers):
                idx = max(idx, self._SEVERITY_ORDER.index("Medium"))

        if self._is_dc_specific_risk(risk_id, model, rationale):
            idx = min(idx + 1, len(self._SEVERITY_ORDER) - 1)

        if cat == "exposure":
            idx = min(idx + 1, len(self._SEVERITY_ORDER) - 1)

        return self._SEVERITY_ORDER[idx]
