import re

from dojo.models import Finding

# rkhunter does not grade its checks. A warning can be a genuine rootkit indication or an artefact of
# the environment - "the kernel modules directory is missing" is normal inside a container - so
# everything imports at one level and the docs page says to triage by check.
DEFAULT_SEVERITY = "Medium"

# Every log line is prefixed with a bracketed clock time.
TIMESTAMP = re.compile(r"^\[\d{2}:\d{2}:\d{2}\]\s?")

# A check's outcome is a bracketed word at the end of the line: OK, Not found, Warning, Skipped...
RESULT = re.compile(r"\[ (?P<result>[A-Za-z][A-Za-z ]*?) \]\s*$")

WARNING_RESULT = "Warning"

# rkhunter follows a flagged check with one or more "Warning: ..." lines explaining it.
DETAIL_PREFIX = "Warning:"

# Other line prefixes rkhunter uses. A line starting with one of these begins a new statement, so it
# must not be glued onto the previous warning as a continuation.
OTHER_PREFIXES = ("Info:", "Error:", "Checking", "Performing")

# Header lines worth attaching to every finding, since a log describes one machine and nothing in an
# individual check identifies it.
CONTEXT_PATTERNS = (
    ("Rootkit Hunter version", re.compile(r"Running Rootkit Hunter version (?P<value>\S+) on (?P<host>\S+)")),
    ("Operating system", re.compile(r"Info: Found O/S name: (?P<value>.+)$")),
)


class RkhunterParser:

    """Parses the rkhunter.log written by `rkhunter --check`."""

    def get_scan_types(self):
        return ["rkhunter Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "rkhunter Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the rkhunter.log written by `rkhunter --check --sk --nocolors` "
            "(normally /var/log/rkhunter.log)."
        )

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        lines = [TIMESTAMP.sub("", line).rstrip() for line in content.splitlines()]
        context = self.collect_context(lines)

        findings = []
        for index, line in enumerate(lines):
            match = RESULT.search(line)
            if not match or match.group("result") != WARNING_RESULT:
                continue
            check = self.check_name(line[: match.start()])
            findings.append(
                self.build_finding(check, self.details_after(lines, index), context, test),
            )
        return findings

    def collect_context(self, lines):
        context = {}
        for line in lines:
            for label, pattern in CONTEXT_PATTERNS:
                if label in context:
                    continue
                if found := pattern.search(line):
                    context[label] = found.group("value").strip()
                    if "host" in found.groupdict():
                        context.setdefault("Host", found.group("host").strip())
        return context

    def details_after(self, lines, index):
        """
        Collect the "Warning: ..." lines that explain a flagged check.

        rkhunter writes the explanation after the result line, and not every flagged check has one -
        two of the four in a default container run do not - so this stops at the next check result
        rather than assuming a one-to-one pairing.
        """
        details = []
        for line in lines[index + 1:]:
            if RESULT.search(line):
                break
            stripped = line.strip()
            if stripped.startswith(DETAIL_PREFIX):
                details.append(stripped[len(DETAIL_PREFIX):].strip())
            elif stripped.startswith(OTHER_PREFIXES):
                # A new statement, not a continuation: rkhunter interleaves Info: lines between
                # warnings, and gluing one on would put unrelated text inside the finding.
                continue
            elif details and stripped:
                # A genuine continuation, which rkhunter writes as an indented line.
                details[-1] = f"{details[-1]} {stripped}"
        return details

    def check_name(self, text):
        """
        Clean the check's wording into a title.

        One line in a default run is both a result and its own warning -
        "Warning: Suckit Rootkit additional checks [ Warning ]" - so a leading "Warning:" is dropped
        rather than left in the title.
        """
        text = text.strip()
        if text.startswith(DETAIL_PREFIX):
            text = text[len(DETAIL_PREFIX):].strip()
        return text

    def build_finding(self, check, details, context, test):
        # No file_path or line: rkhunter inspects a running system, not a file. Some warnings name a
        # path in prose, but extracting one would be guesswork.
        return Finding(
            test=test,
            # rkhunter has no check identifiers, so the check's own wording is the only name a
            # finding has.
            title=check or "rkhunter warning",
            severity=DEFAULT_SEVERITY,
            description=self.build_description(check, details, context),
            static_finding=False,
            dynamic_finding=True,
        )

    def build_description(self, check, details, context):
        parts = []
        if check:
            parts.append(f"**Check:** {check}")
        parts.extend(f"**Warning:** {detail}" for detail in details)
        if not details:
            # Saying so beats leaving the reader wondering whether something was lost.
            parts.append("**Warning:** rkhunter flagged this check without an explanatory message.")
        parts.extend(f"**{label}:** {value}" for label, value in sorted(context.items()))
        return "\n".join(parts)
