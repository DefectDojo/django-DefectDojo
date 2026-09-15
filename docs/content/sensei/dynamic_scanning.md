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
- **Environment**: a label (Production, Staging, Development, Other). It is descriptive, and it
  is also matched against deploy events (see [Scanning on deploy](#scanning-on-deploy)).
- **Scanner**: which engine runs against the target (see [Choosing a scanner](#choosing-a-scanner)).
- **API Schema**: shown only for the Schemathesis scanner. The OpenAPI/Swagger schema to fuzz,
  as a URL or a path in the repository. Leave it blank to use the target origin's
  `/openapi.json`.
- **Allowed Host Scope**: optional. The hosts a scan is permitted to reach, for example
  `*.example.com`. Leave it blank to allow the target host only. The scope is enforced by the
  egress boundary, not by the scan configuration, so a scan cannot wander outside it even if a
  page redirects.
- **Scan on deploy**: optional. Automatically launch a scan of this target when its repository
  and environment are deployed (see [Scanning on deploy](#scanning-on-deploy)).

Targets attach to a saved configuration, so the panel appears when you are editing an existing
repository. In the multi-repository onboarding flow there is no saved configuration to attach a
target to yet; save first, then reopen the configuration to add targets.

## Choosing a scanner

Each target runs one of three open-source engines, so you can match the depth of the scan to
the target:

- **Nuclei**: a fast, request-only baseline that checks for known CVEs and misconfigurations.
  It sends no mutating traffic, needs no authentication, and is the default.
- **ZAP**: a deeper, authenticated active scan that spiders the app and fires mutating,
  injection-style traffic. Sensei seeds ZAP's plan from what it already knows about the code.
- **Schemathesis**: API fuzzing driven by the target's OpenAPI/Swagger schema. It generates
  requests for every documented operation and checks the responses against the contract: no
  server errors, status-code and schema conformance, and so on. Point it at a schema with the
  **API Schema** field.

ZAP and Schemathesis can present authentication on every request when the target needs a signed
session; set that on the target's authentication surface. The credentials are stored encrypted
and are never shown back.

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

## Scanning on deploy

A target can scan itself whenever its environment is deployed, so dynamic scanning keeps pace
with what is actually running instead of waiting for someone to press **Scan**. Turn on **Scan
on deploy** for the target, then connect the repository's GitHub App so Sensei receives its
deployment events.

When GitHub reports a **successful** deployment, Sensei launches a scan of every target on that
repository that has **Scan on deploy** turned on and whose **Environment** matches the one that
was deployed (`production`, `staging`, and `dev` are matched flexibly). A deployment that fails,
or one to an environment no target is watching, launches nothing.

Ownership is still re-checked at launch, exactly as for a manual scan, so a deploy never turns a
lapsed or revoked verification into a scan. Deploy-triggered scans are only sent for GitHub
targets today.

## Scheduling scans

A target can also run on a recurring schedule, independent of deploys, so a deployed
environment is re-checked on a regular cadence. On a verified target, open the schedule
action and set a cron expression. DAST is the heaviest scan Sensei runs, so a target may be
scheduled at most once per day (a single time of day). Use the deploy trigger for "scan when
it changes" and a schedule for "scan regularly regardless"; a target can use both.

Scheduling uses DefectDojo's scheduling service, so it is available only when that service is
enabled. Ownership is re-checked at each scheduled run, exactly as for a manual or
deploy-triggered scan, so a lapsed or revoked verification stops the next run.

## Limits

The number of dynamic-scanning targets you can onboard is capped by your license. When the cap
is reached, adding another target is declined until you remove one or raise the limit.
