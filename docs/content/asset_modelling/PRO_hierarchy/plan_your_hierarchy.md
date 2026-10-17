---
title: "Plan your hierarchy"
description: "Decide how Organizations and Assets should map to your teams, systems and reports, with a copyable LLM prompt that drafts the tree for you"
draft: false
audience: pro
weight: 1
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: parent and child Assets and the five priority fields are DefectDojo Pro features. The advice on Organizations and Assets applies to Open Source as well, which makes this a good page to read before moving from Open Source to Pro.</span>

Your hierarchy is the set of Organizations you create and the Assets inside them, including which Assets sit under which parents. Its shape decides how your reports group Findings, which Findings deduplicate against each other, and who can see what. It is worth an hour of planning.

It is not worth waiting for. Assets can be moved between Organizations and re-parented later without losing Findings, history or deduplication state, so the usual best path is to sketch a reasonable tree, get scan data flowing on day one, and adjust once you see real data. [You can reorganize later](../reorganize_later/) explains what changes and what does not when you do.

## Why the structure matters

### Reporting

Most metrics, dashboards and reports filter by Organization or by Asset. It is easier to combine several small Organizations into one report than to split one large Organization into several, so make Organizations as granular as your reporting needs and no more. If you will report on individual departments, a division-level Organization only adds a layer you have to filter through.

Parent links matter for reporting too. Metrics can **Include child assets**, and the hierarchy diagram shows each Asset's Findings plus the Findings of the Assets below it, so a parent is a natural roll-up point for a system made of several parts.

### Deduplication scope

Deduplication works inside one Asset by default: a Finding is compared with the Findings already in its own Asset, and an Engagement can narrow that further. Placing two Assets under the same parent or the same Organization does **not** make their Findings deduplicate against each other. If the same scanner results arrive in two Assets, you get two sets of Findings.

So split Assets where you want separate Finding histories (for example, a production deployment and a feature branch), and keep things in one Asset where you want one history. When you deliberately model several Assets but still want them to share matching, use a [Dedupe Pool](/triage_findings/finding_deduplication/pro__dedupe_pools/). See [About Deduplication](/triage_findings/finding_deduplication/about_deduplication/) for the full rules.

### Access

Access comes from roles on Organizations and roles on individual Assets:

* A role on an Organization gives access to every Asset in it, and to their Engagements, Tests and Findings. With non-exclusive membership turned on, access follows every Organization an Asset belongs to, not only its primary one.
* A role on an Asset gives access to that Asset only.

**A parent Asset does not change who can see an Asset.** A role on a parent gives no access to its children, a role on a child gives no access to its parent or its siblings, and nesting Organizations of the same type grants nothing either. If a group of people needs to see a set of Assets, put those Assets in an Organization the group has a role on, or give the group roles on the Assets themselves. See [Set User Permissions](/admin/user_management/set_user_permissions/).

### Priority

Two of the five priority fields, **Revenue** and **User Records**, are weighed as a share of the totals across the Asset's Organization. The same revenue figure counts for more in a small Organization than in a large one, so decide your Organization boundaries before you spend time on those numbers. The fields are described [below](#plan-the-five-priority-fields-alongside-the-tree).

## Three common patterns

Most hierarchies are one of these three, or a mix. Each example shows Organizations at the top level and nested Assets below them.

### Team-based Organizations

One Organization per team that owns and fixes the code.

```
Payments Team [Organization]
├── payments-api
├── payments-worker
└── checkout-web
Identity Team [Organization]
├── auth-service
└── admin-portal
```

**Choose it when** remediation is owned by teams and reports go to team leads. Access lines up with ownership: give each team a role on its own Organization.

**Watch for** reorganizations of the company. When teams merge or split, Assets move between Organizations. That is safe to do, but it is a recurring task.

### Technology-domain Organizations

One Organization per kind of thing being scanned, such as applications, cloud infrastructure, containers or networks.

```
Applications [Organization]
├── payments-api
└── auth-service
Cloud Infrastructure [Organization]
├── aws-prod-account
└── aws-staging-account
Container Images [Organization]
└── base-images
```

**Choose it when** separate specialist teams handle each domain (an AppSec team, a cloud security team, a network team) and each reports on its own area. It also maps cleanly onto scanning tools, because most tools cover one domain.

**Watch for** ownership. A domain Organization does not say which development team fixes a Finding, so record that with Asset contacts, tags or, with non-exclusive membership, an additional Team-type Organization.

### Environment-aware nesting

Organizations by team or domain, with nested Assets that separate environments or branches under one parent.

```
Payments Team [Organization]
└── payments-api
    ├── payments-api/prod
    ├── payments-api/staging
    └── payments-api/dev
        └── payments-api/dev/feature-x
```

**Choose it when** the same code is scanned in several environments or branches and you want each to keep its own Finding history, while still reporting on the whole service from the parent.

**Watch for** Asset count. Every child is a separate Asset with its own deduplication and its own priority fields, so nest only where the separation earns its keep.

**Mixing patterns.** Organizations carry a type (Team, Business Application, Compliance Scope, Portfolio or Custom). With non-exclusive membership turned on, one Asset can sit in a Team Organization, a Compliance Scope and a Portfolio at once, so you do not have to choose a single pattern for every purpose. See [Organizations](/asset_modelling/engagements_tests/pro__organizations/#organization-types).

## Plan the five priority fields alongside the tree

DefectDojo Pro ranks Findings by Priority and Risk using facts about the Asset that holds them. Scanners never supply these facts, because they are about your business rather than the code. Until someone fills them in, every Asset looks alike and Priority rests on severity and exploit data alone. They are quick to answer while you are already discussing each Asset's place in the tree.

| Field | What to record | A quick way to decide |
| --- | --- | --- |
| **Business Criticality** | None, Very Low, Low, Medium, High or Very High | Rank Assets against each other. Reserve Very High for the handful the business cannot run without. |
| **User Records** | An estimate of the user records the Asset stores or can reach | An order of magnitude is enough (1,000 or 1,000,000). |
| **Revenue** | An estimate of the annual revenue the Asset supports | Use one currency everywhere. It is compared within the Organization. |
| **External Audience** | True if people outside your organization use it | Customers, partners or the public count. |
| **Internet Accessible** | True if it can be reached from the internet | Answer for the deployed system, not the repository. |

Two more settings apply to every Asset and come with defaults, so you only plan for them if the defaults do not fit:

* **Prioritization Engine.** A built-in engine applies to every Asset. Create another and assign it only where a group of Assets should weigh the factors differently. See [Prioritization Engines](/asset_modelling/pro_hierarchy/priority_sla/#prioritization-engines).
* **SLA Configuration.** New Assets use the Default SLA Configuration. See [Apply an SLA Configuration to an Asset](/asset_modelling/pro_hierarchy/priority_sla/#apply-an-sla-configuration-to-an-asset-pro).

The values do not need to be exact. Priority is relative, so the goal is to make your most important Assets stand out. All five are on the **Edit Asset** form, and **Business Criticality** can also be set for many Assets at once from **Bulk Edit** on the All Assets list. To review what is filled in, [export the Asset inventory](/asset_modelling/engagements_tests/pro__assets/#export-the-asset-inventory): the export includes all five fields. See [Priority Fields: Asset-Level](/asset_modelling/pro_hierarchy/priority_sla/#priority-fields-asset-level) for how each one is used.

## Draft a hierarchy with an LLM

An LLM is good at turning a description of your teams, systems and tools into a first draft of the tree. The prompt below does not connect to DefectDojo or change anything: it interviews you, proposes a structure with its reasoning and trade-offs, and lists the priority fields to fill in. You then build the result in DefectDojo yourself.

### Before you start

Have these to hand. Rough answers are fine.

1. **Your environment.** The applications, services, repositories, cloud accounts and other things you scan, and roughly how many of each.
2. **Your team structure.** Who builds and fixes what, and who should be able to see which results.
3. **Your scanning tools.** Which tools you use, how they group results today (projects, sites, accounts, repositories), and whether you import from CI, by hand or through Connectors.
4. **Your reporting needs.** Who reads security reports, and at what level: per team, per product, per business unit, per compliance scope.
5. **Your current hierarchy, if you have one.** If you are moving from Open Source or reorganizing, an export of your Assets and Organizations helps the model work from what exists.

### The prompt

Copy the entire fenced block below and paste it into Claude, ChatGPT, or any other capable LLM. The prompt is self-contained: the model will ask you about your environment, teams, tools and reporting, then walk you through discovery → proposal → checks → priority fields.

```text
You are helping me plan the hierarchy of Organizations and Assets in
DefectDojo Pro, a vulnerability management platform. You are a planning
partner only: you do not connect to DefectDojo and you do not change
anything. Ask before you assume.

================================================================================
DATA MODEL
================================================================================

DefectDojo organizes security data in this hierarchy:

  Organization   a top-level grouping: a team, business unit, domain,
                 compliance scope or portfolio. Not scanned directly.
  Asset          something that is tested: an application, service,
                 repository, cloud account, container image, host.
                 Assets can have ONE parent Asset in the same Organization,
                 so Assets form trees.
  Engagement     a period or stream of testing on one Asset (a CI pipeline,
                 a pen test, a connector sync).
  Test           one scan or test run inside an Engagement.
  Finding        one vulnerability reported by a Test.

Organizations can have a type: Team, Business Application, Compliance Scope,
Portfolio or Custom. Organizations of the same type can be nested for
navigation. Some instances allow an Asset to belong to additional
Organizations besides its primary one ("non-exclusive membership"); ask me
whether mine does before relying on it.

================================================================================
RULES THAT SHAPE A GOOD HIERARCHY
================================================================================

1. REPORTING. Reports and metrics filter by Organization or Asset. It is
   easier to combine small Organizations than to split a big one. Metrics can
   include child Assets, so a parent is a natural roll-up point.

2. DEDUPLICATION. Findings deduplicate only within their own Asset by
   default. Sharing a parent or an Organization does NOT make two Assets
   deduplicate against each other. Split Assets where separate Finding
   histories are wanted; keep one Asset where one history is wanted. A
   "Dedupe Pool" can deliberately share matching across chosen Assets.

3. ACCESS. Access comes from roles on Organizations (which cover every Asset
   in them) and roles on individual Assets. A parent Asset does NOT change
   who can see an Asset: a role on a parent gives no access to its children,
   and a role on a child gives no access to its parent. Nested Organizations
   grant nothing either. Never propose parent links as a way to grant or
   restrict access.

4. PRIORITY. Five Asset fields drive Finding Priority and Risk, and scanners
   never supply them:
     business_criticality  none, very low, low, medium, high, very high
     user_records          estimated user records stored or reachable
     revenue               estimated annual revenue supported (one currency)
     external_audience     true if people outside the organization use it
     internet_accessible   true if reachable from the internet
   Revenue and user records are weighed as a share of the totals across the
   Asset's Organization. A built-in Prioritization Engine applies to every
   Asset by default; only suggest another engine where a group of Assets
   clearly needs different weighting.

5. REORGANIZING IS SAFE. Assets can later move between Organizations (their
   child Assets move with them) and be re-parented, without losing Findings,
   history or deduplication state. Prefer a simple structure that can start
   today over a perfect one that delays importing data.

================================================================================
COMMON PATTERNS
================================================================================

A. Team-based Organizations: one Organization per owning team. Access and
   remediation line up with ownership. Company reorganizations mean moving
   Assets.
B. Technology-domain Organizations: Applications, Cloud Infrastructure,
   Containers, Network. Fits specialist security teams and maps onto tools.
   Ownership must be recorded another way (contacts, tags, or an additional
   Team Organization).
C. Environment-aware nesting: Organizations by team or domain, with child
   Assets per environment or long-lived branch under one parent (service ->
   service/prod, service/staging, service/dev). Each child keeps its own
   Finding history; the parent rolls them up.

Mixing patterns is normal. Say which pattern each part of the tree follows.

================================================================================
WORKFLOW
================================================================================

1. DISCOVERY. Ask me, a few questions at a time:
   - my environment: what I scan and roughly how many of each;
   - my team structure: who builds and fixes what, and who may see what;
   - my scanning tools: which tools, how each groups results (projects,
     sites, accounts, repositories), and how results arrive (CI, manual
     upload, connectors);
   - my reporting needs: who reads reports, at what level;
   - whether my instance has non-exclusive membership turned on;
   - my current hierarchy, if I have one (I may paste an export).
   Summarize what you heard and let me correct it before proposing anything.

2. PROPOSAL. Propose a hierarchy as an indented tree:
   - Organizations at the top level, marked [Organization] with their type;
   - Assets nested under their parents, using names my tools already use
     where possible, so connectors and CI imports land in the right place;
   - for large repeating sets (hundreds of accounts or repositories), show
     the rule and two or three examples instead of every item.
   After the tree, give:
   - the rationale: which pattern each part follows and why;
   - the trade-offs: what this structure makes harder, and the main
     alternative I could choose instead;
   - who should get a role on which Organization or Asset.

3. CHECKS. Review your own proposal against these four questions and report
   each answer plainly:
   - Dedupe: will the same results ever land in two Assets? Are Assets split
     only where separate histories are wanted?
   - Access: can every group see exactly what it needs through Organization
     or Asset roles, without relying on parent links?
   - Reporting: can each report I described be produced by filtering on
     Organizations or parent Assets?
   - Maintainability: what happens when a team reorganizes, a service is
     added, or a tool is replaced? How much manual upkeep does this need?
   Revise the proposal if a check fails, and say what you changed.

4. PRIORITY FIELDS. For each Asset (or each rule for a repeating set),
   suggest values for the five priority fields as a table, marking every
   value you guessed so I can confirm it. Ask me for anything you cannot
   reasonably infer. Note any group of Assets that might need its own
   Prioritization Engine or SLA Configuration, and why.

5. SETUP ORDER. Finish with the order to build it in DefectDojo: create
   Organizations, create or import Assets, set parents, fill priority
   fields, assign roles. Remind me that reorganizing later is safe.

================================================================================
HARD CONSTRAINTS
================================================================================

- Do NOT invent tools, teams or systems I did not mention. Ask.
- Do NOT use parent links to control access.
- Do NOT assume non-exclusive membership is available unless I confirm it.
- Do NOT put an Asset's parent in a different Organization.
- Keep names exactly as my tools report them unless I ask you to rename.
- If a question has no clear answer, give me the two best options with
  their trade-offs and let me choose.

Start by asking me about my environment and my team structure.
```

### How to use it

1. **Paste the prompt** above into Claude, ChatGPT, or another capable LLM.
2. **Answer its discovery questions.** It will ask about your environment, teams, tools and reporting, and whether your instance uses non-exclusive membership. Correct its summary before it proposes anything.
3. **Review the tree, the rationale and the trade-offs.** Ask for the alternative it mentions if the first proposal does not fit, or ask it to redo one branch.
4. **Read its checks.** It should answer the dedupe, access, reporting and maintainability questions for its own proposal, and revise the tree if one fails.
5. **Confirm the priority fields.** Every guessed value is marked. Fix the guesses, then fill the values in on the **Edit Asset** form as you build each Asset.

> **💡 Tip:** If the model proposes parent Assets as a way to give a team access to a group of Assets, push back. Parent links do not grant access. Ask it to express the same intent with an Organization the team has a role on, or with roles on the Assets themselves.

## Check the result

Whether the tree came from a workshop or an LLM, run these four checks before you build it.

**Dedupe**

* Will the same scanner results ever arrive in two Assets? If so, one of them should go, or the two should share a [Dedupe Pool](/triage_findings/finding_deduplication/pro__dedupe_pools/).
* Is every split between Assets one where you really want separate Finding histories?

**Access**

* Can each team see exactly what it needs through roles on Organizations or on Assets?
* Does any part of the plan rely on a parent Asset to grant or limit access? It cannot.

**Reporting**

* Can each report you need be produced by filtering on one or more Organizations, or on a parent Asset with its children included?
* Will any Organization be so large that every report on it needs further filtering?

**Maintainability**

* When a team reorganizes, how many Assets move? Moving is safe, but frequent large moves suggest Organizations by domain or product rather than by team.
* When a new service or account appears, is it obvious where it goes? Connectors and CI imports should be able to name its Asset without a person deciding each time.
* Are there layers that exist only for tidiness? Every extra level is something to maintain.

## Setup order

1. Create the Organizations, with their types.
2. Create the Assets, or let your Connectors and CI imports create them, using the names your tools already report.
3. Set parent Assets from the **Asset Hierarchy** screen or the **Edit Asset** form.
4. Fill in the five priority fields, starting with your most critical Assets.
5. Give teams roles on their Organizations, and on individual Assets where needed.

Then look at real data for a few weeks and adjust. [You can reorganize later](../reorganize_later/) covers what each kind of change does.

## Next steps

* [You can reorganize later](../reorganize_later/): what changes and what stays put when you move Assets or re-map Connector Records.
* [Asset Hierarchy](../asset_hierarchy/): parent and child Assets, the hierarchy diagram, and more nesting examples.
* [Organizations](/asset_modelling/engagements_tests/pro__organizations/) and [Assets](/asset_modelling/engagements_tests/pro__assets/): what each level holds and where its boundaries are.
* [Assign Priority, Risk and SLAs](/asset_modelling/pro_hierarchy/priority_sla/): how the five fields feed Priority and Risk.
