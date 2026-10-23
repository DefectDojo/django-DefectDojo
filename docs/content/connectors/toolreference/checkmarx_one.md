---
title: "Checkmarx One"
description: "How to set up the Checkmarx One Upstream Connector for DefectDojo"
weight: 33
audience: pro
---
DefectDojo's Checkmarx One connector calls the Checkmarx API to fetch data.

#### **Connector Mappings**

1. Enter your **Tenant Name** in the **Checkmarx Tenant** field. This name should be visible on the Checkmarx One login page in the top\-right hand corner:   
" Tenant: \<**your tenant name**\> "  
​
![image](images/connectors_tool_reference_2.png)

2. Enter a valid API key. You may need to generate a new one: see [Checkmarx API Documentation](https://docs.checkmarx.com/en/34965-68618-generating-an-api-key.html#UUID-f3b6481c-47f4-6cd8-9f0d-990896e36cd6_UUID-39ccc262-c7cb-5884-52ed-e1692a635e08) for details.
3. Enter your tenant location in the **Location** field. This URL is formatted as follows:  
​`https://<your-region>.ast.checkmarx.net/` . Your Region can be found at the beginning of your Checkmarx URL when using the Checkmarx app. **<https://ast.checkmarx.net>** is the primary US server (which has no region prefix).

#### **Branch handling**

By default, each sync imports the findings of a project's **single most recent completed scan, regardless of branch**. If your CI scans many branches, whichever branch happened to scan last "wins" that sync: findings that only exist on other branches are not imported, and the sync's close-old reconciliation can churn findings open and closed as different branches take turns being the latest scan.

Two optional fields control this behavior:

- **Branch**: pins every project to one branch name — only scans of that branch are imported. This is a single global value for the whole connector, so it fits fleets where every project uses the same long-lived branch (e.g. `main`).
    - A **`*` wildcard** is supported. A Branch value containing `*` selects across *every* matching branch rather than a single one — for example `release/*` imports each release branch, and `*` matches every branch. Combined with **Track Scanned Branches**, this is the way to track a family of branches without tracking all of them.
    - If a wildcard matches **no** branch within the scan window, that sync is **skipped** rather than treated as "the branch has no findings" — so a pattern that temporarily matches nothing cannot close every finding on the asset.
- **Track Scanned Branches**: when enabled, each sync finds every branch with a completed scan in the project's recent scan history and imports **the latest completed scan of each branch**, one reimport per branch. Each branch's findings live in their own engagement on the mapped asset, named "\<default engagement\> \- \<branch\>", so closing stale findings is scoped per branch: a fix merged to one branch can never close another branch's findings. The project's primary branch (as reported by Checkmarx) is imported first, so re-occurrences of the same finding on other branches deduplicate against the primary branch's original.

Notes on **Track Scanned Branches**:

- **Check which default applies to you.** Branch tracking is **on by default for new installations**. Installations that predate the change keep their previous behavior, so the toggle is off for them until someone turns it on.
- When both fields are set, only the pinned **Branch** is tracked — including when that Branch value is a wildcard pattern, in which case every branch matching the pattern is tracked.
- A branch that stops being scanned (merged or deleted) stops receiving updates: its engagement remains visible with its last-known findings, which you can review and close in bulk.
- Turning the toggle off later is safe: per-branch engagements simply stop receiving imports and the default engagement resumes on the next sync.
- Connectors reconcile state on the sync schedule. Branch tracking makes each sync complete across branches; it does not make data real-time between syncs.

#### **Result States**

By default, the connector imports findings in every Checkmarx result state except **Not Exploitable**. To import only findings in some states, fill in the optional **Result States** field.

- Enter a comma-separated list, for example `CONFIRMED,URGENT`. Custom states also work, for example `DD_READY`.
- Case and spaces do not matter. `dd ready`, `DD Ready` and `DD_READY` are the same state.
- Leave the field blank to import every state.
- The connector never imports **Not Exploitable** findings, even if you list that state.
- The filter applies to SAST, SCA, IaC and DAST results. If your DAST results cannot carry a custom state, a list of only custom states imports no DAST findings.
- If a finding leaves a listed state, the next sync closes it in DefectDojo.
- If no finding has a listed state, the sync imports nothing and closes the findings that the connector imported before. Check the spelling against your Checkmarx custom states before you save.

#### **Triage state, Exploitable Path and comments**

The connector carries three pieces of Checkmarx triage data onto each finding, so you can filter on them in the Findings list, in Custom Dashboards and in the Report Builder.

- **State.** Every finding (SAST, SCA, IaC and DAST) that has a Checkmarx state is tagged `cx-state:<state>` with its Checkmarx result state in lowercase: `cx-state:to_verify`, `cx-state:confirmed`, `cx-state:urgent`, `cx-state:proposed_not_exploitable`. A custom state such as `DD Ready` becomes `cx-state:dd_ready`, and any space, comma or quote in a state name becomes `_`. A finding has at most one state tag. A result that Checkmarx returns with no state gets none.
- **Exploitable Path.** When [Exploitable Path](https://docs.checkmarx.com/en/34965-19120-exploitable-path.html) is enabled on the Checkmarx project and a SAST scan has run, each SCA finding is tagged `exploitable-path:found` if Checkmarx found a call path from your code to the vulnerable method, or `exploitable-path:none` if it looked and found no path. A finding with neither tag was not analysed, which is different from being safe.
- **Comments.** The comment a Checkmarx user wrote when triaging a result is stored in the finding's **Severity Justification**, prefixed with `Checkmarx comment:`. It is shown on the finding page and in Report Builder detail blocks. SCA and DAST results carry comments today. SAST results do not, because the Checkmarx SAST results API does not return them. IaC results do not either: the connector leaves the IaC comment field out until it is confirmed to hold the triage note.

Unlike other tags, **the state and Exploitable Path tags follow the tool.** When a sync matches a finding that already exists, DefectDojo replaces that finding's `cx-state:` and `exploitable-path:` tags with the ones the sync reports, so a result moved from To Verify to Confirmed in Checkmarx shows as `cx-state:confirmed` here after the next sync. Tags outside those two families, including ones you added yourself, are never touched. The Severity Justification is refreshed the same way on active and reactivated findings, unless someone edited it in DefectDojo, in which case your edit is kept. A finding marked False Positive, Out of Scope or Risk Accepted still gets its tags updated, but keeps its Severity Justification.

Notes:

- The tags do not change deduplication and are never added to Unique ID From Tool or the description.
- The connector owns the `cx-state:` and `exploitable-path:` tag families. A tag you add by hand in either family is replaced by what Checkmarx reports on the next sync, so use a different prefix for your own tags.
- This applies to connector syncs only. Reimporting a Checkmarx One file through the regular import keeps the tags and Severity Justification a finding was first imported with.
- Findings that already existed before this version gain the tags on their next sync. They gain the comment only if their Severity Justification is blank; a justification already on the finding is treated as yours and kept.
- A finding whose state changes to Not Exploitable is still closed on the next sync, as before; it is not kept with a `cx-state:not_exploitable` tag.

#### **Tagging findings with the Checkmarx scan ID**

Each Checkmarx One finding's **Unique ID From Tool** is its Checkmarx result hash. A result hash alone does not locate a finding in Checkmarx; you also need the ID of a scan that contains it. Turn on **Tag Findings With Scan ID** to record that scan ID on the findings the connector imports.

When the toggle is on, every finding a sync imports (SAST, SCA, KICS and DAST) is tagged `scan-id:<scan id>`, where the ID is the Checkmarx scan the connector pulled the finding from. With **Track Scanned Branches** on, each branch's findings carry the ID of that branch's own scan. You can filter findings by the tag, or read it through the API together with Unique ID From Tool.

Notes:

- The toggle is **off by default**, and turning it on does not change deduplication: the scan ID is only a tag. It is never added to Unique ID From Tool or the description.
- **The tag records the scan in which DefectDojo first imported the finding.** A later sync that matches an existing finding keeps that finding's tags, so the tag is not replaced with each new scan ID. That scan contains the finding, so it still locates the finding in Checkmarx, unless Checkmarx's data retention has since deleted the scan.
- Findings already in DefectDojo when you turn the toggle on do not get the tag. Only findings created by later syncs do.
