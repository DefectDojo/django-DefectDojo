---
title: "PSIRT"
description: "Product Security Incident Response: advisory feeds, SBOM matching, and advisory publishing"
summary: ""
date: 2026-08-04T00:00:00+00:00
lastmod: 2026-08-04T00:00:00+00:00
draft: false
weight: 6
chapter: true
sidebar:
  collapsed: true
seo:
  title: ""
  description: ""
  canonical: ""
  noindex: false
---

DefectDojo Pro's PSIRT module helps product security teams answer one question
continuously: **am I vulnerable to this new advisory?** It ingests security
advisories from the publishers you choose, matches them against your software
inventory, and turns confirmed exposure into DefectDojo findings.

PSIRT is a Pro feature in beta. It requires the **PSIRT** feature flag (which
depends on **Locations**) and the **PSIRT Advisory Engine** license
entitlement.

### If you don't see PSIRT in the menu

The PSIRT flag depends on **Locations**, and a flag with an unmet dependency is
forced off — so with Locations disabled, PSIRT is off no matter how its own
switch is set, and none of its pages are reachable. Settings → Feature Flags
says so on the PSIRT row ("Requires Locations to be enabled"). Enable Locations
first; it is environment-sourced, so it needs a restart to take effect.

If the entries are visible but locked, that is the other gate: the licence.
PSIRT needs the **PSIRT Advisory Engine** entitlement, and a locked entry
explains what to ask for.

## How it fits together

1. **[Advisory Feeds](feeds/)** — choose which publishers to poll. Every source
   ships disabled; enabling one records your acceptance of its terms.
2. **[Import SBOM](import-sbom/)** — give PSIRT an inventory to match against.
3. **[Components](components/)** — that inventory as PSIRT reads it, plus the
   judgement you add to it: a risk rating, an authoritative CPE, tags.
4. **[Matching Rules](matching-rules/)** — optional. For advisories that publish
   no machine-readable version ranges, where structural matching has nothing to
   compare. Also where you preview a rule, check coverage per asset, and see
   whether a rule has earned its keep.
5. **[Feed Findings](feed-findings/)** — the queue. Each advisory leads with an
   explicit answer to "am I affected?", and confirming a match files a DefectDojo
   finding.
6. **[Cases and SLA](cases/)** — group related matches into work items and track
   the triage obligation on them.
7. **[Advisories](advisories/)** — write, review and publish your *own* advisories
   about your own products, with fingerprint-bound signoffs and honest delivery
   states.
8. **[PSIRT dashboard](dashboard/)** — a shared template that leads with the
   affected question, beside whether the pipeline is actually working.

Two pages are configuration rather than workflow:

- **[SLA Policies](sla-policies/)** — how long each severity tier gets before a
  triage clock warns and breaches.
- **[PSIRT Settings](settings/)** — the case-worthiness calibration, the "new"
  item window, and which upstream changes count as material.

You do not need all of it. Feeds plus an inventory is enough to start getting
answers; rules, cases and SLAs are for teams that want the workflow around them,
and advisory publishing is for teams that ship software to customers who need to
be told.

Everything up to step 6 is about what other people published. Step 7 is the other
direction — what you publish — and it is a separate job with separate approvals.
