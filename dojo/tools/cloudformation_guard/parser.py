import json
import re

from dojo.models import Finding


class CloudFormationGuardParser:

    """
    Parser for AWS CloudFormation Guard.

    ``cfn-guard validate --output-format json`` reports each rule that a template failed under
    ``not_compliant``, alongside ``compliant`` and ``not_applicable`` lists that are not findings.

    Each failing rule holds a list of checks, and each check is a clause that did not hold. The
    clause shape depends on the comparison cfn-guard made: a ``Unary`` check for existence tests
    such as ``BucketEncryption exists``, and a ``Binary`` check for comparisons such as
    ``CidrIp != '0.0.0.0/0'``. Both are walked here, because a parser that only understood one of
    them would silently drop half of a real report.

    cfn-guard can also emit one JSON document per validated file, concatenated. Both a single
    document and a JSON array of documents are accepted.
    """

    # cfn-guard records the position of the offending property as [L:4,C:6]. It appears appended
    # to the resource path, and inside the human readable message as Path=<path>[L:4,C:6].
    PATH_POSITION = re.compile(r"^(?P<path>.*?)\[L:(?P<line>\d+),C:(?P<column>\d+)\]$")
    MESSAGE_POSITION = re.compile(r"Path=(?P<path>\S*?)\[L:(?P<line>\d+),C:(?P<column>\d+)\]")

    def get_scan_types(self):
        return ["CloudFormation Guard Scan"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return (
            "Import CloudFormation Guard reports in JSON format, generated with "
            "'cfn-guard validate --data <template> --rules <rules> --output-format json'."
        )

    def get_findings(self, file, test):
        data = json.load(file)
        reports = data if isinstance(data, list) else [data]

        findings = []
        for report in reports:
            if not isinstance(report, dict):
                continue
            template = report.get("name")
            for entry in report.get("not_compliant") or []:
                rule = entry.get("Rule") or {}
                findings.extend(self._rule_findings(rule, template, test))
        return findings

    def _rule_findings(self, rule, template, test):
        rule_name = rule.get("name") or "cfn-guard rule"
        checks = rule.get("checks") or []
        if not checks:
            # A failing rule with no clause detail is still a failure worth importing.
            return [self._to_finding(rule_name, template, {}, test)]
        return [self._to_finding(rule_name, template, self._clause_detail(check), test) for check in checks]

    def _clause_detail(self, check):
        """Flatten a Unary or Binary clause into the fields a Finding needs."""
        clause = check.get("Clause") or {}
        # The clause holds exactly one comparison kind; take whichever is present.
        body = {}
        for kind in ("Unary", "Binary"):
            if isinstance(clause.get(kind), dict):
                body = clause[kind]
                body = {**body, "_kind": kind}
                break
        if not body:
            return {}

        check_body = body.get("check") or {}
        # check is keyed by whether cfn-guard could resolve the queried property at all.
        resolution = {}
        for state in ("UnResolved", "Resolved"):
            if isinstance(check_body.get(state), dict):
                resolution = {**check_body[state], "_state": state}
                break

        value = resolution.get("value") or {}
        traversed = value.get("traversed_to") or {}
        # A Binary check reports the offending value under from/to rather than traversed_to.
        if not traversed and isinstance(resolution.get("from"), dict):
            traversed = resolution["from"]

        return {
            "kind": body.get("_kind"),
            "state": resolution.get("_state"),
            "context": body.get("context"),
            "custom_message": (body.get("messages") or {}).get("custom_message"),
            "error_message": (body.get("messages") or {}).get("error_message"),
            "path": traversed.get("path"),
            "resource_value": traversed.get("value"),
            "reason": value.get("reason") or resolution.get("reason"),
            "remaining_query": value.get("remaining_query"),
            "comparison": resolution.get("comparison"),
        }

    def _to_finding(self, rule_name, template, detail, test):
        path, line = self._split_position(detail.get("path"))
        if line is None:
            # The position is usually only in the message text, not on the path itself.
            line = self._line_from_messages(
                detail.get("error_message"), detail.get("reason"), path,
            )

        description = [
            str(text).strip()
            for text in (detail.get("custom_message"), detail.get("error_message"), detail.get("reason"))
            if text and str(text).strip()
        ]
        description.append(f"**Rule:** {rule_name}")
        if template:
            description.append(f"**Template:** {template}")
        if detail.get("context"):
            description.append(f"**Clause:** {str(detail['context']).strip()}")
        if detail.get("kind"):
            description.append(f"**Check type:** {detail['kind']}")
        if detail.get("state"):
            description.append(f"**Property resolution:** {detail['state']}")
        if detail.get("remaining_query"):
            description.append(f"**Missing property:** {detail['remaining_query']}")
        if path:
            description.append(f"**Resource path:** {path}")
        if detail.get("resource_value") is not None:
            description.append(f"**Value found:** {json.dumps(detail['resource_value'])}")
        if detail.get("comparison"):
            description.append(f"**Comparison:** {detail['comparison']}")

        return Finding(
            title=f"{rule_name}: {path}" if path else rule_name,
            test=test,
            description="\n".join(description),
            # cfn-guard reports compliance, not exploitability. See the docs page for why this
            # is a documented constant rather than a derived gradient.
            severity="Medium",
            file_path=template or None,
            line=line,
            component_name=path or None,
            vuln_id_from_tool=rule_name,
            static_finding=True,
            dynamic_finding=False,
        )

    def _split_position(self, path):
        """Separate the resource path from the [L:n,C:n] position cfn-guard appends to it."""
        if not path:
            return None, None
        match = self.PATH_POSITION.match(path)
        if match:
            return match.group("path"), int(match.group("line"))
        return path, None

    def _line_from_messages(self, *candidates):
        """
        Recover the template line from cfn-guard's message text.

        The messages embed positions as Path=/Resources/X/Y[L:13,C:18]. A binary check names two
        paths, the offending value and the value it was compared against, and the second is a
        literal from the rule file reported at [L:0,C:0]. The resource path is passed in last so
        the position belonging to it can be preferred over that literal.
        """
        wanted_path = candidates[-1]
        positions = []
        for text in candidates[:-1]:
            if not text:
                continue
            positions.extend(self.MESSAGE_POSITION.finditer(str(text)))
        for match in positions:
            if wanted_path and match.group("path") == wanted_path:
                return int(match.group("line"))
        for match in positions:
            line = int(match.group("line"))
            if line:
                return line
        return None
