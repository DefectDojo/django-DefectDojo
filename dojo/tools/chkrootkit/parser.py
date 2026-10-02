import re

from dojo.models import Finding

# chkrootkit does not grade its results. An INFECTED verdict is far more serious than a WARNING, so
# those two are separated, but there is no score behind either - and in practice a container run
# produces WARNINGs about unsupported filesystems that say nothing about the host's security.
SEVERITIES = {
    "INFECTED": "High",
    "WARNING": "Medium",
    "VULNERABLE BUT DISABLED": "Low",
}
DEFAULT_SEVERITY = "Medium"

# Full output pairs a check with its verdict, e.g.
#   Checking `basename'...                                      not infected
#   Searching for for hidden directories using chkdirs...       WARNING
RESULT = re.compile(
    r"^\s*(?P<check>(?:Checking|Searching for|Verifying)\b.*?)\.\.\.\s+(?P<result>\S.*?)\s*$",
)

# Verdicts that mean nothing was found. Everything else is treated as a problem, so a verdict this
# parser has not seen before is reported rather than silently dropped.
CLEAN_RESULTS = {
    "not found",
    "not infected",
    "not tested",
    "nothing found",
    "nothing detected",
    "nothing deleted",
    "no suspect files",
    "no suspect files found",
    "not vulnerable",
    "started",
    # chkrootkit brackets a multi-part test with started/finished status lines rather than verdicts.
    "finished",
    "skipped",
    "ok",
}

# Explanatory lines, which appear on their own and are the ONLY output `chkrootkit -q` produces.
WARNING_LINE = re.compile(r"(?:^|\s)WARNING:\s*(?P<text>.+?)\s*$")


class ChkrootkitParser:

    """Parses the text output of `chkrootkit`."""

    def get_scan_types(self):
        return ["chkrootkit Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "chkrootkit Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Import the output of `chkrootkit` (full) or `chkrootkit -q` (problems only)."

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        findings = []
        current = None
        for line in content.splitlines():
            if not line.strip():
                continue

            match = RESULT.match(line)
            if match:
                verdict = match.group("result").strip()
                if self.is_clean(verdict):
                    current = None
                    continue
                current = self.build_finding(match.group("check").strip(), verdict, test)
                findings.append(current)
                continue

            warning = WARNING_LINE.search(line)
            if not warning:
                continue
            text = warning.group("text").strip()
            if current is not None:
                # An explanation of the check that just failed.
                current.description += f"\n**Warning:** {text}"
            else:
                # `chkrootkit -q` prints only these lines, with no check line to attach them to, so
                # they have to stand on their own or a quiet report would import as clean.
                findings.append(self.build_warning_finding(text, test))
        return findings

    def is_clean(self, verdict):
        return verdict.lower() in CLEAN_RESULTS

    def severity_for(self, verdict):
        upper = verdict.upper()
        for marker, severity in SEVERITIES.items():
            if upper.startswith(marker):
                return severity
        return DEFAULT_SEVERITY

    def build_finding(self, check, verdict, test):
        # No file_path or line: chkrootkit inspects a running system rather than reading a file.
        return Finding(
            test=test,
            # chkrootkit has no check identifiers, so its own wording names the finding.
            title=f"{check}: {verdict}",
            severity=self.severity_for(verdict),
            description=f"**Check:** {check}\n**Verdict:** {verdict}",
            static_finding=False,
            dynamic_finding=True,
        )

    def build_warning_finding(self, text, test):
        return Finding(
            test=test,
            title=text,
            severity=SEVERITIES["WARNING"],
            description=f"**Warning:** {text}",
            static_finding=False,
            dynamic_finding=True,
        )
