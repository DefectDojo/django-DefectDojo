---
title: "Root Cause Correlation"
description: "Group Findings that share a root cause -- the same vulnerable component, CVE, infrastructure resource, or weakness at a URL -- so one fix can be traced to every Finding it resolves"
weight: 1
audience: pro
---

A vulnerable library pulled into forty services produces forty Findings. Each one is real, each
one is separately triaged, and each one is fixed by the same single version bump. **Root Cause
Correlation** makes that relationship explicit: DefectDojo Pro groups Findings that share a root
cause into a ranked list of **Root Causes**, so you can see the one fix and everything it clears.

Correlation is **additive and non-destructive**. Every Finding stays independently visible,
keeps its own status, and is triaged exactly as before. Correlation only adds links between
Findings, the cluster nodes those links roll up into, and the evidence that produced each link.

> **Correlation is not deduplication.** [Deduplication](/triage_findings/finding_deduplication/)
> decides that two reports describe the *same* Finding and marks one a duplicate. Correlation
> relates *different* Findings that happen to share a cause, and never marks anything a
> duplicate. The two run independently and can both be enabled.

## Enabling Root Cause Correlation

Root Cause Correlation is in **Beta**, is gated behind a feature flag, and is **off by default**.
A superuser can turn it on from **Settings > Feature Flags** on both Cloud and On-Premise
instances. See [Feature Flags](/admin/feature_flags/pro__feature_flags/).

While the flag is off, the engine does no work at all: no clusters are built, no links are
created, and nothing is dispatched after an import.

After turning the flag on, existing Findings are **not** correlated retroactively until either
they are next imported or you run a backfill (see
[Backfilling existing Findings](#backfilling-existing-findings)).

## What gets correlated

Correlation groups on four signals. Three of them are **exact** -- a link is only created where
two Findings genuinely name the same thing -- and one is a labelled heuristic.

| Root Cause type | Findings are grouped when they... | Example | Match |
|---|---|---|---|
| **Component** | reference the same software component at the same version | `log4j-core 2.14.1` | Exact |
| **CVE** | reference the same CVE identifier | `CVE-2021-44228` | Exact |
| **Resource** | name the same infrastructure object | `aws_s3_bucket.logs` | Exact |
| **Endpoint** | report the same weakness class at the same URL | `CWE-79 at example.com/search` | Heuristic |

A Finding joins **every** cluster that applies to it, not just one. An SCA Finding for
`log4j-core 2.14.1` carrying three CVEs joins four Root Causes: its component cluster and one
cluster per CVE. That is what lets a container-image Finding that reports only a CVE correlate
with the SCA Finding that reports the component.

### Component matching

Where the Locations data model is in use, components are keyed on the **Package URL (purl)**,
with qualifiers and subpaths stripped, so the same package reported against different distros
or architectures forms one cluster rather than several. Findings that only carry the legacy
`component_name` / `component_version` fields are keyed on those instead.

Findings with no usable component are skipped rather than grouped: a missing version, or the
`unknown-package` placeholder some SBOM formats emit, would otherwise collapse every
component-less row into one meaningless cluster.

### CVE matching

CVE identifiers are upper-cased and trimmed, so `cve-2021-44228` and `CVE-2021-44228` land in
the same cluster. Only CVE identifiers match — GHSA, GO, RUSTSEC and other advisory prefixes are
recognised as vulnerability ids elsewhere in DefectDojo but do not form Root Causes yet.

### Resource matching

Cloud posture (CSPM) and infrastructure-as-code (IaC) tools report a **resource** rather than a
package: an S3 bucket, a Kubernetes namespace, a Terraform resource block. Those Findings carry a
name but no version, so they are not software components and are not matched as such.

Resource matching groups them on the resource identifier, case-folded so tools that spell it
differently still agree. It is an exact join, and it is what lets an IaC Finding about
`aws_s3_bucket.logs` sit in the same Root Cause as the runtime CSPM Finding about the deployed
bucket.

Only qualified identifiers are matched -- a resource name carries a type or path separator
(`.`, `/`, `:`). A bare single word is ignored, so a Finding whose scanner simply omitted the
component version is not swept into a resource cluster it has nothing to do with.

### Endpoint matching

Two DAST tools scanning the same application will often both report the same weakness at the same
URL. Endpoint matching groups those: the Root Cause is a **weakness class at a location**, for
example `CWE-79 at example.com/search`.

This is the one **heuristic** signal, and it is labelled as such everywhere it appears. A shared
purl or CVE is an identity; "same CWE, same URL" is a judgement, and a reviewer should be able to
weigh it differently. The cluster detail marks every member with its match type.

The CWE is required. A URL on its own is a place, not a cause -- grouping every Finding at
`/search` regardless of what is wrong with it would produce large, meaningless clusters.

Query strings, fragments and ports are ignored when comparing URLs, so `/search?q=a` and
`/search?q=b` are the same place, as are the same service on 443 and 8443.

> **This does not correlate SAST with DAST.** Static findings identify a source file and dynamic
> findings identify a URL; mapping between the two requires a route map DefectDojo does not have.
> Endpoint matching relates dynamic findings to each other.

### When a CVE is already covered by a component

A Finding joins its component cause *and* each of its CVE causes, so an SCA Finding for
`log4j-core 2.14.1` carrying two CVEs produces three Root Causes. Left alone, all three compete
for the top of the ranked list — but only one of them is a piece of work. Bumping `log4j-core`
to a fixed version clears both CVEs outright; there is no separate "fix CVE-2021-44228" action.

So a CVE Root Cause is marked **covered** when *every* one of its active member Findings is also
an active member of a single component or resource cause. Covered causes are hidden from the
Root Causes page by default, keeping the list to things you can actually act on.

The moment **one** member sits outside that component, the CVE stands on its own again. That is
the container-image Finding that reports only a CVE with no component attached: no component fix
reaches it, so the CVE is genuinely separate work. This is exactly the cross-domain case
correlation exists to surface, and it is never hidden.

Turn on **Show covered CVEs** above the table to see them. Each one is labelled with the cause
that covers it, so it is clear which fix clears it. Covered causes are only hidden from the
default list — they keep their members, evidence and feedback, they remain reachable from a
Finding's Root Causes panel, and a saved link to one still opens.

Coverage is re-evaluated on every run, in both directions: a CVE stops being covered as soon as
an uncovered Finding appears, and becomes covered again once that Finding is fixed or triaged
away. Rejecting a link takes that member out of the calculation too, since you have said it does
not belong.

Component and resource causes are never marked covered, even when their members overlap
another's. Each one has its own version to bump, so each is real work.

### Which Findings are eligible

Only live, actionable Findings are correlated. A Finding is excluded while it is inactive,
mitigated, a duplicate, a false positive, out of scope, or risk accepted. Findings drop out of
their clusters as they are triaged, so a Root Cause's counts always describe outstanding work.

## Reading the Root Causes page

Open **Root Causes** in the **Manage** section of the sidebar. The page lists every Root Cause
you have access to, ranked so the largest, riskiest ones come first.

| Column | What it tells you |
|---|---|
| **Root Cause** | The component and version, or the CVE |
| **Type** | Component, CVE, Resource or Endpoint |
| **Fix** | The version that fixes it, when the cluster's members agree on one |
| **CVEs** | Every CVE seen across the cluster's members (component clusters) |
| **Active Findings** | How many outstanding Findings this one cause accounts for |
| **Assets** | Blast radius — how many Assets are affected |
| **Organizations** | Blast radius — how many Organizations are affected |
| **Risk** | Aggregate risk, summed from the severities of the active members |
| **Muted** | Whether the cluster has been muted |

CVE causes that a component or resource cause already covers entirely are hidden unless
**Show covered CVEs** is on; see
[When a CVE is already covered by a component](#when-a-cve-is-already-covered-by-a-component).

### Narrowing the list to your Assets or Organizations

A Root Cause is portfolio-wide by design: one cluster can span many Assets across many
Organizations. When several teams share an instance, that is more than any one team needs to
see at once. The **Assets** and **Organizations** columns each carry a filter that scopes the
list to the causes reaching the Assets or Organizations you pick, so a team can pull the whole
portfolio down to just the Root Causes relevant to it. Filtering this way selects *which* causes
appear; it does not change the counts on the rows that remain — each still reports its full blast
radius, scoped to your access, not the slice that matched the filter. Both columns also sort on
their count, so you can rank by how widely a cause has spread.

Selecting a row opens the cluster, listing each member Finding with its severity, Asset,
domain, **match** type, and the **evidence** that links it. Evidence is recorded per link, so a
cluster can always explain itself: a component link records the purl it matched on, a CVE link
records the identifier, an endpoint link records the URL and the CWE. The **Match** column reads
`exact` for component, CVE and resource links and `heuristic` for endpoint links, so a judgement
is never presented as an identity.

The blast-radius counts in the cluster header are the drill-downs behind the **Assets** and
**Organizations** columns. A count on its own is not actionable when it can read "400 Assets", so
clicking either count opens a breakdown — one row per Asset, or per Organization — most-affected
first, name-searchable, with each row's own Finding count and worst scores. The per-Organization
breakdown also shows how many of that Organization's Assets the cause reaches, and the per-Asset
breakdown drills one step further into that Asset's member Findings.

Aggregate risk is a deterministic sum over the active members' severities (Critical 100, High
70, Medium 40, Low 10, Info 1). It does not depend on the prioritization engine being enabled.

**Fix** is taken from the members' own fix versions, and is only shown when every member that
reports one reports the same one. Scanners disagree, and a CVE cluster can span components that
are each fixed at a different version, so where there is no single answer the column is left
empty rather than picking one.

### What you see is scoped to your access

Members, counts and blast radius are filtered to the Findings you are authorized to see, and the
ranking is computed after that filtering. Two users with different Product access will therefore
see different counts for the same Root Cause, and a cluster whose members you cannot see does
not appear for you at all.

## Where else correlation shows up

### On a Finding

A Finding's own page carries a **Root Causes** panel listing every cluster it belongs to, split
into the vulnerable component (or resource) and the CVEs it shares. That is usually where
correlation is most useful: you are already triaging one Finding and it tells you the fix is
shared. Links you have rejected do not reappear there.

### In finding priority

A Root Cause that spans many Assets makes each of its member Findings more urgent, because the
single fix clears all of them. Priority therefore rises with the **blast radius of the widest
Root Cause a Finding belongs to**:

- A cluster confined to one Asset adds nothing -- there is no "one fix clears many" story.
- Each additional affected Asset adds a little more, up to a cap, so one very wide cluster
  cannot outweigh severity.
- The widest cluster counts, not the sum of all of them, so a Finding is not pushed up merely for
  carrying many CVE ids.
- Links you have **rejected** stop counting. A **muted** cluster still counts: muting hides it
  from the ranked list, it does not say the Findings are unrelated.

The weight is tunable per Asset as the **Correlation** multiplier in the Prioritization Engine,
alongside Severity, Exploitability, Endpoints and Reachability. The whole term disappears when the
feature flag is off, so scores are unchanged on an instance that does not use correlation.

### On a dashboard

**Top Root Causes** is available as a dashboard widget, listing the highest-ranked clusters with
their finding counts, affected Assets and risk. Add it from the widget picker; it appears there
only while the feature is enabled. Its counts are scoped to your access in the same way the page
is.

## Giving feedback on a cluster

Correlation is a judgement about your data, so you can correct it.

- **Confirm** a member to record that the link is right.
- **Reject** a member to record that it is not, which removes it from the cluster's active
  member list.
- **Mute** a whole Root Cause to stop it competing for attention in the ranked list. **Unmute**
  restores it.

Feedback is durable. Ordinary reimport churn — a Finding being mitigated and later reactivating
— will not erase a confirm or a reject, and a muted cluster is never cleaned up even when it
temporarily has no members. Only links the system created on its own are reconciled away when
they stop applying.

## How and when correlation runs

Correlation runs **automatically and asynchronously after every import and reimport**, over the
Findings that import affected. It is best-effort: a failure inside correlation is logged and
swallowed, and never fails the import that triggered it.

Because it is idempotent, re-running it over the same Findings converges on the same result
rather than duplicating anything. As Findings change, the engine also reconciles: a component
version bump moves the Finding to the new cluster and prunes the old one once it is empty.

### Backfilling existing Findings

To correlate Findings that predate the feature being enabled, run the management command. Omit
the argument to recompute the whole portfolio, or scope it to a single Asset:

```bash
python manage.py recompute_correlations
python manage.py recompute_correlations --product-id 42
```

## What the API exposes

Root Causes are readable over the standard API, so you can pull them into a report, open tickets
from them, or track them as a metric without going through the UI.

- `GET /api/v2/root_causes/` lists them, ranked the same way the page is.
- `GET /api/v2/root_causes/{id}/` returns one Root Cause plus its member Findings, each with the
  evidence that links it and whether the match was exact or heuristic.

Both are read-only. Confirming, rejecting and muting are done from the UI for now; those are
deliberately not published while the feature is in Beta, so that adding them later cannot break
anything you have already built against.

Filters on the list: `cause_type` (`exact` or `in`), `muted`, `identity_key` (`exact` or
`icontains`) and `display_name__icontains`. Two membership filters scope the list the way the
Assets and Organizations columns do in the UI: `product` takes one or more Asset ids and
`prod_type` takes one or more Organization ids (comma-separated), returning only the Root Causes
that reach them. Membership selects which causes are listed and leaves each cause's counts at its
full, access-scoped blast radius.

`GET /api/v2/root_causes/{id}/organizations/` returns the per-Organization breakdown behind
`organization_count` — one row per affected Organization, most-affected first, with its Finding
count and how many of its Assets the cause reaches.

Two behaviors worth knowing before you script against it:

- **Counts are scoped to the token's access**, exactly as they are in the UI. Two tokens with
  different Product access will report different `active_member_count`, `product_count`,
  `organization_count` and `risk_score` for the same Root Cause. This is intended -- the numbers
  describe what *that* caller can see -- so do not treat them as portfolio-wide totals.
- **Covered CVE causes are left out of the list** but are always retrievable by id. Pass
  `?include_subsumed=true` to include them; a Root Cause id you stored earlier keeps working
  through `GET /api/v2/root_causes/{id}/` even after it becomes covered. Each covered cause
  carries `subsumed_by_id` and `subsumed_by_name` so you can see which fix clears it.

If the feature flag is off, both endpoints return **403**, not 404 -- the endpoint exists, it is
simply not enabled.

## Interaction with Global Component Deduplication

[Global Component Deduplication](/triage_findings/finding_deduplication/pro__global_component_deduplication/)
marks cross-Asset SCA Findings as duplicates, and duplicates are not correlated. With both
features on, a Root Cause's member count therefore reflects the surviving originals rather than
every occurrence. The two also key on different things — Global Component matches on component
name and version, while correlation uses the full Package URL — so enabling both is supported
but the counts they produce are not directly comparable.
