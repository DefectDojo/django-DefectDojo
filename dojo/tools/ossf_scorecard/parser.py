import json

from dojo.models import Finding


class OSSFScorecardParser:

    """
    Parser for OpenSSF Scorecard JSON reports.

    Scorecard grades a repository's supply chain posture on a set of independent checks,
    each scored from 0 to 10. A score of -1 means the check could not reach a conclusion --
    usually because it lacks the access or the metadata it needs -- which is not the same as
    a failure and is not imported.
    """

    # Scorecard's score is out of 10, where 10 is a fully passing check.
    MAX_SCORE = 10
    INCONCLUSIVE = -1

    def get_scan_types(self):
        return ["OpenSSF Scorecard"]

    def get_label_for_scan_types(self, scan_type):
        return scan_type

    def get_description_for_scan_types(self, scan_type):
        return "Import OpenSSF Scorecard JSON, generated with 'scorecard --repo=<repo> --format=json'."

    def get_findings(self, file, test):
        data = json.load(file)
        repo = (data.get("repo") or {}).get("name")
        commit = (data.get("repo") or {}).get("commit")
        scorecard = data.get("scorecard") or {}
        aggregate = data.get("score")

        findings = []
        for check in data.get("checks", []):
            score = check.get("score")
            if score is None or score == self.INCONCLUSIVE or score >= self.MAX_SCORE:
                continue
            findings.append(
                self._to_finding(check, score, repo, commit, scorecard, aggregate, test),
            )
        return findings

    def _to_finding(self, check, score, repo, commit, scorecard, aggregate, test):
        name = check.get("name")
        documentation = check.get("documentation") or {}

        description = []
        if documentation.get("short"):
            description.append(documentation["short"])
        description.extend([
            f"**Check:** {name}",
            f"**Score:** {score} of {self.MAX_SCORE}",
        ])
        if check.get("reason"):
            description.append(f"**Reason:** {check['reason']}")
        if repo:
            description.append(f"**Repository:** {repo}")
        if commit:
            description.append(f"**Commit:** {commit}")
        if aggregate is not None:
            description.append(f"**Aggregate score:** {aggregate}")
        if scorecard.get("version"):
            description.append(f"**Scorecard version:** {scorecard['version']}")
        description.extend(f"- {detail}" for detail in check.get("details") or [])

        return Finding(
            title=f"{name}: scored {score} of {self.MAX_SCORE}",
            test=test,
            description="\n".join(description),
            severity=self._severity(score),
            component_name=repo,
            vuln_id_from_tool=name,
            references=documentation.get("url") or None,
            static_finding=True,
            dynamic_finding=False,
        )

    def _severity(self, score):
        """Scorecard scores out of 10; the further below the maximum, the worse the posture."""
        if score <= 3:
            return "High"
        if score <= 6:
            return "Medium"
        return "Low"
