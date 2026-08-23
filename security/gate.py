#!/usr/bin/env python3
"""Security Gateway.

Агрегирует SARIF-отчёты сканеров, считает находки по severity, при превышении
порога роняет пайплайн (exit 1) и оставляет комментарий со сводкой и
рекомендациями в Pull Request.

Порог задаётся переменной окружения GATE_FAIL_ON (CRITICAL|HIGH|MEDIUM|LOW).
"""
import argparse
import glob
import json
import os
import sys
import urllib.request
from collections import Counter, defaultdict

SEV_ORDER = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]


def sev_from_result(result, rules):
    """SARIF result -> severity bucket."""
    rule_id = result.get("ruleId", "")
    props = rules.get(rule_id, {}).get("properties", {})
    score = props.get("security-severity") or result.get("properties", {}).get("security-severity")
    if score is not None:
        try:
            s = float(score)
        except ValueError:
            s = None
        if s is not None:
            if s >= 9.0:
                return "CRITICAL"
            if s >= 7.0:
                return "HIGH"
            if s >= 4.0:
                return "MEDIUM"
            return "LOW"
    level = result.get("level", "warning")
    return {"error": "HIGH", "warning": "MEDIUM", "note": "LOW"}.get(level, "MEDIUM")


def load_rules(run):
    rules = {}
    driver = run.get("tool", {}).get("driver", {})
    for r in driver.get("rules", []):
        rules[r.get("id", "")] = r
    return rules


def parse_sarif(path):
    findings = []
    try:
        with open(path, encoding="utf-8") as fh:
            data = json.load(fh)
    except Exception as exc:  # noqa: BLE001
        print(f"[gate] пропуск {path}: {exc}")
        return findings
    for run in data.get("runs", []):
        tool = run.get("tool", {}).get("driver", {}).get("name", os.path.basename(path))
        rules = load_rules(run)
        for res in run.get("results", []):
            rule = rules.get(res.get("ruleId", ""), {})
            loc = ""
            locs = res.get("locations", [])
            if locs:
                phys = locs[0].get("physicalLocation", {})
                uri = phys.get("artifactLocation", {}).get("uri", "")
                line = phys.get("region", {}).get("startLine", "")
                loc = f"{uri}:{line}" if line else uri
            findings.append({
                "tool": tool,
                "rule": res.get("ruleId", ""),
                "severity": sev_from_result(res, rules),
                "message": (res.get("message", {}) or {}).get("text", "")[:200],
                "location": loc,
                "help": rule.get("helpUri", "") or (rule.get("help", {}) or {}).get("text", "")[:200],
            })
    return findings


def post_pr_comment(body):
    token = os.environ.get("GITHUB_TOKEN")
    event_path = os.environ.get("GITHUB_EVENT_PATH")
    repo = os.environ.get("GITHUB_REPOSITORY")
    if not (token and event_path and repo):
        print("[gate] нет данных для комментария в PR — пропуск")
        return
    try:
        with open(event_path, encoding="utf-8") as fh:
            event = json.load(fh)
        pr = event.get("pull_request", {}).get("number")
    except Exception:  # noqa: BLE001
        pr = None
    if not pr:
        print("[gate] это не PR — комментарий не оставляем")
        return
    url = f"https://api.github.com/repos/{repo}/issues/{pr}/comments"
    req = urllib.request.Request(
        url,
        data=json.dumps({"body": body}).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {token}",
            "Accept": "application/vnd.github+json",
            "Content-Type": "application/json",
        },
        method="POST",
    )
    try:
        urllib.request.urlopen(req, timeout=30)
        print("[gate] комментарий оставлен в PR")
    except Exception as exc:  # noqa: BLE001
        print(f"[gate] не удалось оставить комментарий: {exc}")


def build_report(findings, counts, threshold, blocked):
    status = "❌ РЕЛИЗ ОСТАНОВЛЕН" if blocked else "✅ Проверки пройдены"
    lines = [f"## Security Gateway — {status}", ""]
    lines.append(f"Порог блокировки: **{threshold}** и выше.")
    lines.append("")
    lines.append("| Severity | Найдено |")
    lines.append("|---|---|")
    for sev in reversed(SEV_ORDER):
        lines.append(f"| {sev} | {counts.get(sev, 0)} |")
    lines.append("")
    # топ блокирующих находок с рекомендациями
    thr_idx = SEV_ORDER.index(threshold)
    blocking = [f for f in findings if SEV_ORDER.index(f["severity"]) >= thr_idx]
    if blocking:
        lines.append("### Блокирующие находки (топ-15)")
        lines.append("")
        lines.append("| Severity | Инструмент | Правило | Где | Рекомендация |")
        lines.append("|---|---|---|---|---|")
        for f in blocking[:15]:
            rec = f["help"] or "—"
            lines.append(f"| {f['severity']} | {f['tool']} | `{f['rule']}` | {f['location']} | {rec} |")
        if len(blocking) > 15:
            lines.append("")
            lines.append(f"…и ещё {len(blocking) - 15}. Полный список — в артефактах и DefectDojo.")
    return "\n".join(lines)


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--reports", default="reports")
    args = ap.parse_args()

    threshold = os.environ.get("GATE_FAIL_ON", "HIGH").upper()
    if threshold not in SEV_ORDER:
        threshold = "HIGH"

    findings = []
    for path in glob.glob(os.path.join(args.reports, "*.sarif")):
        findings.extend(parse_sarif(path))

    counts = Counter(f["severity"] for f in findings)
    thr_idx = SEV_ORDER.index(threshold)
    blocked = any(SEV_ORDER.index(f["severity"]) >= thr_idx for f in findings)

    report = build_report(findings, counts, threshold, blocked)
    print(report)

    # step summary
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as fh:
            fh.write(report + "\n")

    post_pr_comment(report)

    if blocked:
        print(f"\n[gate] найдены уязвимости уровня {threshold}+ — останавливаем релиз")
        sys.exit(1)
    print("\n[gate] порог не превышен")


if __name__ == "__main__":
    main()
