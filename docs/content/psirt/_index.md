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

## How it fits together

1. **[Advisory Feeds](feeds/)** — choose which publishers to poll. Every source
   ships disabled; enabling one records your acceptance of its terms.
2. **[Import SBOM](import-sbom/)** — give PSIRT an inventory to match against.
3. **[Matching Rules](matching-rules/)** — optional. For advisories that publish
   no machine-readable version ranges, where structural matching has nothing to
   compare.
4. **[Feed Findings](feed-findings/)** — the queue. Each advisory leads with an
   explicit answer to "am I affected?", and confirming a match files a DefectDojo
   finding.
5. **[Cases and SLA](cases/)** — group related matches into work items and track
   the triage obligation on them.

You do not need all five. Feeds plus an inventory is enough to start getting
answers; rules, cases and SLAs are for teams that want the workflow around them.
