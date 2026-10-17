---
title: "How DefectDojo Deduplicates Findings Across Security Tools"
description: "DefectDojo does not scan. It imports findings from 500+ security tools, normalizes them, and deduplicates them within a tool, across tools and across reimports, so each vulnerability reaches remediation as one active Finding."
weight: -1
---
DefectDojo does not scan anything itself. It ingests findings from 500+ security tools, through report files, API imports and connectors, normalizes every result into the same Finding format, and then deduplicates them: within a single tool, across different tools, and across repeated imports of the same scan. The Findings that remain after deduplication are the ones your team remediates, with SLA deadlines, Jira and other ticketing integrations, risk acceptance, and reimports that close Findings once a tool stops reporting them.

This page explains how that matching works and which settings control it. For the day-to-day view of duplicates, see [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/).

## What happens to a Finding on import

1. The parser for the tool reads the report and maps each result onto DefectDojo's Finding fields, such as title, severity, CWE, vulnerability IDs (CVE, GHSA and similar), component name and version, file path and line, endpoints, and the tool's own identifier for the result when it provides one.
2. DefectDojo computes a hash code for each Finding from the fields configured for that tool.
3. On a reimport into an existing Test, each incoming result is first compared with the Findings already in that Test. A match updates the existing Finding instead of creating a new one, and Findings the tool no longer reports can be closed.
4. Every newly created Finding is then compared with the existing Findings in the same Asset, or the same Engagement if the Engagement is isolated. If it matches, it is marked as a duplicate of the oldest matching Finding.
5. The original Findings stay active and carry on into triage and remediation. Duplicates are set to inactive.

Deduplication must be turned on for step 4 to run. In Community Edition, enable **Deduplicate findings** in **System Settings**. In DefectDojo Pro, see [Enabling Deduplication](/triage_findings/finding_deduplication/pro_enabling_product_deduplication/).

## The deduplication algorithms

Each tool is assigned one of four algorithms. In Community Edition the assignment lives in `DEDUPLICATION_ALGORITHM_PER_PARSER` in `dojo/settings/settings.dist.py`, keyed by scan type, and the same algorithm is used for deduplication and for reimport matching. A tool without an entry uses Legacy.

| Algorithm | Setting value | What it compares | Can it match across tools? |
| --- | --- | --- | --- |
| Hash Code | `hash_code` | The hash code built from the tool's configured fields | Yes, when both Findings have the same hash code |
| Unique ID From Tool | `unique_id_from_tool` | The identifier the tool assigned to the result | No, only Findings from the same tool |
| Unique ID From Tool or Hash Code | `unique_id_from_tool_or_hash_code` | The tool's identifier (same tool only) or the hash code | Yes, through the hash code |
| Legacy | `legacy` | Same title or same CWE, plus matching endpoints (or the same file path and line for static findings), plus the same hash code | Yes, under the same hash code condition |

Unique ID From Tool is the most stable choice for tools that give every result a permanent identifier, because the match survives changes to the title, description or line number. It never crosses tools, since one tool's identifiers mean nothing to another.

For Hash Code and for Unique ID From Tool or Hash Code, endpoints are also checked. When either Finding has endpoints, at least one endpoint on each side must match on the attributes listed in `DEDUPE_ALGO_ENDPOINT_FIELDS`, which defaults to host and path. An empty list turns this check off. Unique ID From Tool ignores endpoints.

## Hash code fields per tool

`HASHCODE_FIELDS_PER_SCANNER` in `dojo/settings/settings.dist.py` lists, for each tool, the Finding fields that go into its hash code. A few of the defaults show how different tools are tuned:

| Tool | Default hash code fields |
| --- | --- |
| ZAP Scan | title, cwe, severity |
| Trivy Scan | title, severity, vulnerability_ids, cwe, description |
| Snyk Scan | vuln_id_from_tool, file_path, component_name, component_version |
| Bandit Scan | file_path, line, vuln_id_from_tool |

The fields that can be used are listed in `HASHCODE_ALLOWED_FIELDS`: title, cwe, cwes, vulnerability_ids, line, file_path, payload, component_name, component_version, description, endpoints, unique_id_from_tool, severity, vuln_id_from_tool and mitigation. The values are joined, compared without regard to case, and hashed with SHA-256. `HASH_CODE_FIELDS_ALWAYS` adds the Finding's `service` value to every hash, so two Findings with different services never match on a hash code.

If a tool has no entry, or its entry names a field that is not allowed, DefectDojo falls back to a legacy hash of title, CWE, line, file path and description. The same fallback applies to a Finding with no CWE when `HASHCODE_ALLOWS_NULL_CWE` is false for that tool.

You can override the per-tool algorithm and hash code fields with the `DD_DEDUPLICATION_ALGORITHM_PER_PARSER` and `DD_HASHCODE_FIELDS_PER_SCANNER` environment variables. Existing Findings keep their old hash codes until you run the `dedupe` management command. [Deduplication Tuning (Open Source)](/triage_findings/finding_deduplication/os__deduplication_tuning/) has examples of both.

In DefectDojo Pro the same choices are made in the UI at **Settings > Finding Workflow > Matching Configuration**, where each tool has separate settings for same tool, cross tool and reimport matching. See [Deduplication Tuning (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/).

## Same-tool and cross-tool deduplication

Same-tool deduplication covers the most common case: the same scanner reports the same issue in scan after scan. Any of the four algorithms handles this.

Cross-tool deduplication covers two different tools reporting the same issue, for example two dependency scanners that both flag the same CVE in the same package. Because the tool's own identifier is only compared within a single tool, cross-tool matches always come from the hash code. A Finding from one tool becomes a duplicate of a Finding from another tool when both tools use Hash Code, Unique ID From Tool or Hash Code, or Legacy, and both Findings end up with the same hash code, service and endpoints.

In practice that means configuring both tools to hash the same fields, and choosing fields whose values do not depend on the tool. Vulnerability IDs, CWE, component name and version, file path and line, and endpoints usually carry the same values across tools. Titles and descriptions rarely do, because each vendor writes its own. For example, two SCA tools that both hash `vulnerability_ids`, `component_name` and `component_version` produce the same hash code for the same CVE in the same package version, as long as they report those values identically. If one tool also lists a GHSA ID and the other does not, the vulnerability ID values differ and the hash codes will not match.

When a cross-tool match happens, the original Finding's **Found by** field lists every tool that reported it.

DefectDojo Pro adds more ways to match across tools. The cross tool setting in Matching Configuration can use a different algorithm and field list from same tool matching, the Hash Code algorithm can compare vulnerability IDs and CWEs as sets, and the Global Component, Global Vulnerability ID and Global Locations algorithms match across Assets. See [Deduplication Tuning (Pro)](/triage_findings/finding_deduplication/pro__deduplication_tuning/) and [Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/).

## Deduplication scope: Asset or Engagement

By default a new Finding is compared with Findings anywhere in the same Asset (called a Product in the API and in older versions). Findings in different Assets are not compared.

To narrow the scope, turn on **Deduplication within this engagement only** on an Engagement (in DefectDojo Pro the option is **Isolate Deduplication From Other Engagements**). When either of two Engagements has it enabled, their Findings are never deduplicated against each other. This is useful when Engagements in one Asset represent separate contexts, such as different repositories, and you want each one to keep its own Findings.

DefectDojo Pro can also widen the scope with [Dedupe Pools](/triage_findings/finding_deduplication/pro__dedupe_pools/), which group chosen Assets so their Findings deduplicate against each other.

## Reimport and closing fixed Findings

Reimport sends a new report into an existing Test and compares each incoming result only with the Findings already in that Test, using the tool's algorithm. The Legacy algorithm matches on title and severity during reimport.

1. A result that matches an existing Finding does not create a new Finding. The existing one is left in place, and if it had been mitigated it is reactivated unless you set **Do Not Reactivate**.
2. A result with no match becomes a new Finding, which then goes through normal deduplication against the rest of the Asset.
3. A Finding in the Test that is missing from the new report is mitigated when **Close Old Findings** is on. On the reimport API endpoint, `close_old_findings` defaults to `true`.

A regular import creates a new Test every time. It can also close old Findings if you set `close_old_findings`, which is off by default for imports. It then mitigates active and risk-accepted Findings from the same tool, in the same Engagement (or in the whole Asset with `close_old_findings_product_scope`), whose hash code or unique ID is not in the new report. In both cases only Findings with the same `service` value are considered.

See [Reimport](/import_data/import_intro/reimport/) for the full reimport workflow.

## How duplicates are displayed and linked

A Finding marked as a duplicate gets the Duplicate status, is set to inactive and unverified, and points to its original. On the View Finding page, a duplicate shows an **Original** column linking to the original Finding and a **Duplicate Cluster** listing the other duplicates of the same original. The original shows a **Duplicates** column listing every Finding marked as its duplicate.

The original is always the oldest matching Finding, so a Finding from an earlier import is never turned into a duplicate of a newer one. Chains are flattened: if a Finding that already has duplicates becomes a duplicate itself, its duplicates are pointed at the new original, so every duplicate links directly to one original.

If the matching original has already been mitigated and the same vulnerability shows up again as an active Finding, DefectDojo does not attach the new Finding to the closed one. The new Finding stays active as its own original, so a returning vulnerability is not hidden.

Duplicates are kept by default. To limit how many are stored, enable **Delete Deduplicate Findings** and set **Maximum Duplicates** in System Settings, as described in [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/#delete-deduplicate-findings). When automatic matching misses Findings you believe belong together, you can link them by hand from [Similar Findings](/triage_findings/finding_deduplication/os__similar_findings/).

## From deduplication to remediation

Because duplicates are inactive, remediation work happens on the originals. SLA deadlines are set per Asset ([SLA Configuration](/asset_modelling/os_hierarchy/os__sla_configuration/)). Jira pushes only Findings that are active (and verified, if your settings require it), so duplicates do not open new Jira issues ([Jira](/connectors/os_jira/os__jira_guide/)). DefectDojo Pro can also push Findings to other issue trackers through [Downstream Connectors](/connectors/downstream/about/). Findings you decide not to fix can be covered by a [Risk Acceptance](/triage_findings/findings_workflows/os__risk_acceptance/), and reimports close Findings once the tool stops reporting them.

## Frequently asked questions

### Can DefectDojo deduplicate findings from two different scanners?

Yes. When both tools use the Hash Code, Unique ID From Tool or Hash Code, or Legacy algorithm, a Finding from one tool is marked as a duplicate of a Finding from the other if both have the same hash code, the same service value and matching endpoints. Configure both tools to hash fields that carry the same values across tools, such as vulnerability IDs, CWE, component name and version, or file path and line. Matching on the tool's own unique ID only works within a single tool.

### Does DefectDojo deduplicate across Assets or Products?

Not by default. Deduplication compares Findings within one Asset, or within one Engagement when the Engagement is isolated. DefectDojo Pro can match across Assets with Dedupe Pools and with the Global Component, Global Vulnerability ID and Global Locations algorithms.

### What is the difference between reimport and deduplication?

Reimport compares an incoming report with the Findings in one Test. Matched results never become new Findings, and Findings missing from the report can be closed. Deduplication runs afterwards on the Findings that were created, and compares them with the rest of the Asset or Engagement.

### Which Finding is kept as the original?

The oldest matching Finding. A newer Finding is always marked as the duplicate, and every duplicate links directly to the same original.

### Does DefectDojo delete duplicate Findings?

Not unless you ask it to. Duplicates are kept as inactive Findings linked to their original. Enabling **Delete Deduplicate Findings** with a **Maximum Duplicates** value makes DefectDojo delete the oldest duplicates beyond that limit. The original is never deleted automatically.
