from dojo.models import Finding

# lynis-report.dat is a flat key=value file. Findings live under two repeated keys, and which of the
# two a result used is the only severity signal lynis gives: a warning is something it believes is
# wrong, a suggestion is hardening advice.
FINDING_KEYS = (
    ("warning[]", "Medium"),
    ("suggestion[]", "Low"),
)

# Both values are pipe-delimited: test id | text | details | solution, with a trailing pipe.
FIELD_SEPARATOR = "|"

# lynis writes a bare "-" where a field has no value.
EMPTY = "-"

# Host context worth attaching to every finding, since a Lynis report describes one machine and
# nothing in an individual result identifies it.
CONTEXT_KEYS = (
    ("hostname", "Hostname"),
    ("os_fullname", "Operating system"),
    ("lynis_version", "Lynis version"),
    ("hardening_index", "Hardening index"),
)


class LynisParser:

    """Parses the lynis-report.dat file written by `lynis audit system`."""

    def get_scan_types(self):
        return ["Lynis Scan"]

    def get_label_for_scan_types(self, scan_type):
        return "Lynis Scan"

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import the lynis-report.dat written by `lynis audit system` "
            "(normally /var/log/lynis-report.dat)."
        )

    def get_findings(self, filename, test):
        content = filename.read()
        if isinstance(content, bytes):
            content = content.decode("utf-8", errors="replace")

        results = []
        context = {}
        for line in content.splitlines():
            key, separator, value = line.partition("=")
            if not separator:
                continue
            key = key.strip()
            if key in {name for name, _ in FINDING_KEYS}:
                results.append((key, value))
            elif key in {name for name, _ in CONTEXT_KEYS}:
                # A repeated context key keeps its first value; lynis writes these once.
                context.setdefault(key, value.strip())

        severities = dict(FINDING_KEYS)
        return [
            self.build_finding(value, severities[key], context, test)
            for key, value in results
        ]

    def build_finding(self, value, severity, context, test):
        test_id, text, details, solution = self.split(value)

        # No file_path, line or location: lynis audits a running host rather than reading a file, so
        # there is no source position to report.
        return Finding(
            test=test,
            title=text or test_id or "Lynis finding",
            severity=severity,
            description=self.build_description(test_id, text, details, severity, context),
            # lynis puts a remediation in the fourth field when the test has one.
            mitigation=solution or None,
            static_finding=False,
            # A Lynis run inspects the state of a running machine rather than reading source.
            dynamic_finding=True,
            vuln_id_from_tool=test_id or None,
        )

    def split(self, value):
        """
        Split a pipe-delimited lynis value into test id, text, details and solution.

        A test that omits a field writes a bare "-", and the text is free to contain a pipe itself,
        so the fields are anchored from both ends rather than taken left to right: the id is first,
        the solution and details are the last two before the trailing separator, and whatever is
        left in between is the text.
        """
        parts = value.split(FIELD_SEPARATOR)
        if parts and not parts[-1].strip():
            # Values end with a trailing separator, which leaves an empty final element.
            parts = parts[:-1]
        if len(parts) < 4:
            parts += [""] * (4 - len(parts))

        test_id = self.clean(parts[0])
        details = self.clean(parts[-2])
        solution = self.clean(parts[-1])
        text = self.clean(FIELD_SEPARATOR.join(parts[1:-2]))
        return test_id, text, details, solution

    def clean(self, part):
        part = part.strip()
        return "" if part == EMPTY else part

    def build_description(self, test_id, text, details, severity, context):
        parts = []
        if text:
            parts.append(text)
        if test_id:
            parts.append(f"**Test ID:** {test_id}")
        # Saying which key the result came from makes the severity traceable back to the report.
        parts.append(f"**Result:** {'warning' if severity == 'Medium' else 'suggestion'}")
        if details:
            parts.append(f"**Details:** {details}")
        parts.extend(
            f"**{label}:** {context[key]}" for key, label in CONTEXT_KEYS if context.get(key)
        )
        return "\n".join(parts)
