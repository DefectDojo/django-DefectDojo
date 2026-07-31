import re

from dojo.models import Finding

# A signature match is a detection, not a guess: ClamAV names the signature it matched. What the
# detection is worth still depends on the artifact, so a confirmed hit is often triaged up to
# Critical, which is a judgement about the artifact rather than something clamscan measures.
DEFAULT_SEVERITY = "High"
EMBEDDED_MALICIOUS_CODE_CWE = 506

# clamscan writes one line per file: "<path>: <signature> FOUND" for a hit, "<path>: OK" for a clean
# file, "<path>: Empty file" for an empty one and "<path>: <reason> ERROR" for a file it could not
# read. Only FOUND is a finding. The path can contain colons and spaces, so the suffix is anchored to
# the end of the line and the path is whatever precedes the last ": ".
FOUND = re.compile(r"^(?P<path>.+): (?P<signature>\S+) FOUND$")


class ClamAVParser:

    """Parses the output of `clamscan`."""

    def get_scan_types(self):
        return ["ClamAV Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "ClamAV Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the output of `clamscan`. Use --allmatch to report every signature per file."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = {}
        for raw in content.splitlines():
            line = raw.strip()
            if not line or line.startswith("---"):
                continue
            match = FOUND.match(line)
            if not match:
                # Clean files, unreadable files and the SCAN SUMMARY block all land here. The summary
                # holds an engine version and a scan date, which are deliberately not carried into a
                # finding: they change between runs of an unchanged artifact.
                continue
            path = match.group("path").strip()
            signature = match.group("signature")
            # With --allmatch one file can match several signatures, and each is its own detection.
            # The same signature on the same file is one finding.
            key = (path, signature)
            if key not in findings:
                findings[key] = self.build_finding(path, signature, test)
        return list(findings.values())

    def build_finding(self, path, signature, test):
        return Finding(
            test=test,
            title=f"Malware detected: {signature} in {path}",
            severity=DEFAULT_SEVERITY,
            cwe=EMBEDDED_MALICIOUS_CODE_CWE,
            description=self.build_description(path, signature),
            mitigation=(
                "Remove the file and find out how it reached this location. If the detection is "
                "wrong, record it as a false positive rather than excluding the path."
            ),
            file_path=path,
            # ClamAV's own name for the detection.
            vuln_id_from_tool=signature,
            # clamscan reads files rather than probing a running service.
            static_finding=True,
            dynamic_finding=False,
        )

    def build_description(self, path, signature):
        parts = [f"**File:** {path}", f"**Signature:** {signature}"]
        if signature.endswith(".UNOFFICIAL"):
            # ClamAV appends this to any signature that did not come from its own database, so the
            # detection is only as good as whichever third-party or local database supplied it.
            parts.append(
                "**Note:** the .UNOFFICIAL suffix means this signature came from a database other "
                "than ClamAV's own.",
            )
        return "\n".join(parts)
