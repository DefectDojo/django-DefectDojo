import json

from dojo.models import Finding


class CapaParser:

    """
    Parser for capa JSON reports.

    capa identifies the *capabilities* of an executable — what it is able to do — and maps
    each to MITRE ATT&CK and MBC. It reports no vulnerabilities and assigns no severity, so
    capabilities import as informational intelligence about a sample, tagged with the
    techniques they correspond to.
    """

    def get_scan_types(self):
        return ["capa Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import capa reports in JSON format, generated with 'capa -j <file>'."

    def get_findings(self, file, test):
        data = json.load(file)
        sample = (data.get("meta") or {}).get("sample") or {}
        findings = []
        for rule in (data.get("rules") or {}).values():
            meta = rule.get("meta") or {}
            # capa emits helper rules used only to build other matches; they are not
            # capabilities of the sample in their own right.
            if meta.get("lib") or meta.get("is_subscope_rule"):
                continue
            findings.append(self._to_finding(rule, meta, sample, test))
        return findings

    def _to_finding(self, rule, meta, sample, test):
        name = meta.get("name")
        namespace = meta.get("namespace")
        attack = self._techniques(meta.get("attack"))
        mbc = self._techniques(meta.get("mbc"))

        description = []
        if meta.get("description"):
            description.append(meta["description"])
        description.append(f"**Capability:** {name}")
        if namespace:
            description.append(f"**Namespace:** {namespace}")
        if attack:
            description.append(f"**ATT&CK:** {', '.join(attack)}")
        if mbc:
            description.append(f"**MBC:** {', '.join(mbc)}")
        description.append(f"**Matches:** {len(rule.get('matches') or [])}")
        if sample.get("sha256"):
            description.append(f"**Sample SHA256:** {sample['sha256']}")

        return Finding(
            title=f"{name} ({namespace})" if namespace else name,
            test=test,
            description="\n".join(description),
            # capa describes what a sample can do, not whether it is wrong.
            severity="Info",
            component_name=sample.get("sha256"),
            vuln_id_from_tool=name,
            references="\n".join(meta.get("references") or []) or None,
            static_finding=True,
            dynamic_finding=False,
        )

    def _techniques(self, entries):
        """Capa reports ATT&CK and MBC as objects carrying the technique and its id."""
        values = []
        for entry in entries or []:
            if not isinstance(entry, dict):
                continue
            technique = entry.get("subtechnique") or entry.get("technique") or entry.get("behavior")
            identifier = entry.get("id")
            if technique and identifier:
                values.append(f"{technique} ({identifier})")
            elif technique:
                values.append(technique)
        return values
