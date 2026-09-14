---
title: "Dynamic Scanning (DAST)"
description: "Point dynamic scans at a deployed environment of a repository Sensei already knows, once you have proven you own the domain."
draft: false
audience: pro
weight: 6
---

**Dynamic Scanning (DAST)** runs an active scan against a *running* deployment of a repository
you have already onboarded to Sensei, so the results land on the same
product as the code Sensei already scans, rather than in a standalone report. It is off by default and gated behind a
Sensei license.

Because a dynamic scan sends real traffic at a live system, the workflow is built around one
rule: a scan only ever runs against a target whose domain ownership you have proven. That check
is enforced when you create the target and again at launch, so a verification that lapses in
between stops the next scan.

## Adding a target

Open a repository's Sensei configuration (the **Configure Repository** screen for a saved
repo) and find the **Dynamic Scanning (DAST)** section. Choose **Add target** and fill in:

- **Target URL**: the deployed environment to scan, for example `https://staging.example.com`.
- **Environment**: a label (Production, Staging, Development, Other). It is descriptive only
  and does not change what the scan does.
- **Allowed Host Scope**: optional. The hosts a scan is permitted to reach, for example
  `*.example.com`. Leave it blank to allow the target host only. The scope is enforced by the
  egress boundary, not by the scan configuration, so a scan cannot wander outside it even if a
  page redirects.

Targets attach to a saved configuration, so the panel appears when you are editing an existing
repository. In the multi-repository onboarding flow there is no saved configuration to attach a
target to yet; save first, then reopen the configuration to add targets.

Each target shows an ownership badge: **Unverified** until you complete the challenge below,
**Verified** once you have.

## Proving domain ownership

Select **Verify** on an unverified target. Sensei shows a DNS **TXT** record to publish:

- a **record name** such as `_dd-dast-challenge.staging.example.com`
- a **record value** such as `dd-dast-verify=<token>`

Add that record to your DNS, then choose **Check now**. Sensei resolves the record and, on a
match, marks the target verified. DNS changes take a few minutes to propagate, so if the first
check does not find the record, wait and try again. A verification lasts 90 days.

## Launching a scan

A verified target shows a **Scan** action. Launching asks you to confirm, because it sends live
scan traffic to the target within its allowed host scope. Ownership is re-checked at that moment
and the launch is refused if the target is no longer verified, so a lapsed or revoked
verification can never turn into a scan. Findings are imported back against the repository's
product as they complete.

## Limits

The number of dynamic-scanning targets you can onboard is capped by your license. When the cap
is reached, adding another target is declined until you remove one or raise the limit.
