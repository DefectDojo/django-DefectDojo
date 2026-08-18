import json

from dojo.models import Finding


class BinwalkParser:

    """
    Parser for Binwalk JSON reports.

    Binwalk identifies embedded files, compression, cryptographic constants and licence
    strings inside a firmware image or binary. It reports what a file *contains*, not whether
    it is vulnerable, so results are imported as informational inventory. Binwalk assigns no
    severity; it reports a match confidence instead.
    """

    def get_scan_types(self):
        return ["Binwalk Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import Binwalk reports in JSON format, generated with 'binwalk -l report.json <file>'."

    def get_findings(self, file, test):
        data = json.load(file)
        findings = []
        for entry in data or []:
            analysis = entry.get("Analysis") or entry
            file_path = analysis.get("file_path")
            findings.extend(
                self._to_finding(match, file_path, test)
                for match in analysis.get("file_map") or []
            )
        return findings

    def _to_finding(self, match, file_path, test):
        name = match.get("name")
        offset = match.get("offset")

        description = []
        if match.get("description"):
            description.append(match["description"])
        description.append(f"**Signature:** {name}")
        if offset is not None:
            description.append(f"**Offset:** {offset}")
        if match.get("size") is not None:
            description.append(f"**Size:** {match['size']}")
        if match.get("confidence") is not None:
            description.append(f"**Confidence:** {match['confidence']}")
        if file_path:
            description.append(f"**File:** {file_path}")

        return Finding(
            title=f"{name} signature at offset {offset}" if offset is not None else f"{name} signature",
            test=test,
            description="\n".join(description),
            # Binwalk identifies content; it does not judge it.
            severity="Info",
            file_path=file_path,
            vuln_id_from_tool=name,
            unique_id_from_tool=match.get("id"),
            static_finding=True,
            dynamic_finding=False,
        )
