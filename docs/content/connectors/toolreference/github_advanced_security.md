---
title: "GitHub Advanced Security"
description: "How to set up the GitHub Advanced Security Upstream Connector for DefectDojo"
weight: 64
audience: pro
---
The GitHub Advanced Security connector imports **code scanning**, **Dependabot**, and **secret scanning** alerts from GitHub, as three separate finding types (`GitHub:CodeScanning`, `GitHub:Dependabot`, and `GitHub:SecretScanning`). DefectDojo discovers every non\-archived repository in the configured organization and creates a Record for each one.

It can also import **issues** from each repository's issue tracker as a fourth finding type (`GitHub:Issues`), for teams that record vulnerabilities as ordinary GitHub Issues rather than as security alerts. Issue import is off until you configure it — see [Importing Issues](#importing-issues) below.

#### Prerequisites

GitHub Advanced Security features must be enabled for the repositories you want to import. The connector authenticates with a GitHub **personal access token**:

1. In GitHub, open **Settings \> Developer settings \> Personal access tokens** and create a token owned by (or with access to) the target organization.
2. Grant it read access to the security alerts: a *fine\-grained* token needs **Read\-only** access to **Code scanning alerts**, **Dependabot alerts**, and **Secret scanning alerts** on the organization's repositories; a *classic* token needs the **`repo`** and **`security_events`** scopes.
3. Confirm the token's owner can see the repositories you intend to import — the connector only sees repositories the token can access.

If you also want to import issues, the token needs read access to them: a *fine\-grained* token needs **Read\-only** access to **Issues**, and a *classic* token already has it through the **`repo`** scope. Note that GitHub Advanced Security does **not** need to be enabled to import issues — the issue tracker is available on every repository.

#### Connector Mappings

1. Enter `https://api.github.com` in the **Location** field. For GitHub Enterprise Server, use `https://<your-host>/api/v3`.
2. Enter the organization login in the **Organization** field.
3. Enter the personal access token in the **Secret** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.
5. To import issues as well, set **Issue Labels**, and optionally **Issue Severity Labels** and **Default Issue Severity**. See [Importing Issues](#importing-issues) below.

Each non\-archived repository becomes a Record, queried across the three alert families for open alerts, and for open issues when issue import is configured. A family that is not enabled for a repository is skipped rather than reported as resolved, so disabled features do not cause false closures.

#### Importing Issues

GitHub attaches no severity, CWE, or CVE to an issue — an issue is a tracker entry someone wrote, not scanner output. Two settings therefore decide what gets imported and how it is scored. Both are blank by default, and **no issues are imported until you set a label**, so an existing connector keeps importing only the three alert families.

**Issue Labels** decides which issues qualify. Enter one or more labels, separated by commas. An issue must carry **every** label listed to be imported — GitHub combines them with AND, not OR — so a single label is the usual choice. Nothing about the label has to be security\-related: whatever you use to mark the issues you want in DefectDojo is what you enter here.

**Issue Severity Labels** decides how each imported issue is scored, by mapping your own labels onto DefectDojo severities:

```
Critical=sev-1,blocker; High=sev-2,p1; Medium=sev-3; Low=sev-4; Info=chore
```

Each entry names a DefectDojo severity, then the labels that mean it. Several labels can map to one severity, matching ignores case, and if an issue carries two mapped labels the higher severity wins. Leave this blank if your labels are already severity names — `critical`, `high`, `medium`, `low`, `info` are then matched as they are. If you do set a map, only the labels it names are matched.

**Default Issue Severity** is used for an issue that qualifies but carries no label the map recognizes. It defaults to **Medium**.

An invalid map — a severity DefectDojo does not have, or a label assigned to two different severities — is rejected when you save the connector rather than part\-way through a sync.

#### What to expect from imported issues

* **Pull requests are never imported.** GitHub returns them from the same endpoint as issues, but DefectDojo filters them out, so a pull request carrying your label will not appear as a finding.
* **Closing the issue closes the finding.** Only open issues are read, so an issue you close disappears from the next sync and DefectDojo resolves the finding it produced. Reopening it reopens the same finding rather than creating a second one.
* **The issue body becomes the finding description**, reproduced as written, along with the repository, issue number, author, and labels. Anything written in a GitHub issue therefore reaches DefectDojo.
* **The issue's labels are added to the finding as tags**, so you can filter and build rules on them.
* **These findings carry no CWE, CVE, component, or file path**, because the source has none. They will not deduplicate or correlate against scanner findings for the same vulnerability — if a problem is reported both by a scanner and by a hand\-written issue, DefectDojo holds two findings.
* **A repository with its issue tracker disabled is skipped**, not reported as empty, so turning issues off for a repository does not close the findings already imported from it.
