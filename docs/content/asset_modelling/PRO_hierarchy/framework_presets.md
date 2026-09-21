---
title: "Framework Presets"
description: "Apply a published scheme's patch windows and scan cadence as one preset, preview the plan first, and revert it later"
weight: 3
audience: pro
---

Most of what a framework asks of vulnerability management is a number: patch critical flaws within 14 days, or within 48 hours when an exploit exists, and scan weekly or fortnightly. A framework preset bundles those numbers as DefectDojo Pro settings: SLA configurations, scan cadence policies, a response policy and a set of checks, named after the scheme and the version of it they encode. You apply a preset in one step after previewing exactly what it would change, and you can revert it later.

Framework presets are released behind the Framework Presets feature flag. An administrator turns it on from the Feature Flags page. Until then the Framework Presets settings page and its API answer with a 403.

A preset encodes DefectDojo's reading of a published scheme at a point in time. Confirm the current requirements with the scheme's publisher or with your assessor before relying on the numbers. Applying a preset is not certification, and it does not decide compliance.

## What a preset contains

A preset has four sections. Each entry has a stable id so that applying the same preset again can find what it created the first time.

- SLA configurations: a name, the day counts and enforcement flags per severity, and the Pro extension fields such as the SLA start policy, the CISA KEV cap and the VDR tiers. A severity the scheme is silent about keeps the day count of your default SLA configuration.
- Scan cadence policies: how often each class of asset should be scanned. These are installed disabled, for you to switch on. On a release without scan cadence policies the plan lists them as skipped.
- A response policy: the timeframes severity alone cannot express, such as 48 hours when an exploit exists or when the service is internet-facing. On a release without vulnerability response policies the plan lists it as skipped.
- Checks: questions the scheme wants answered, such as how many active Critical and High findings are older than the patch window. A check names something DefectDojo can count. Where the instance lacks the data, for example vendor support levels on components, the check says the answer is manual.

A preset is data. It contains numbers, names and references to checks that exist in DefectDojo, never code, and every preset is validated against a schema before it is stored.

## The two shipped presets

**UK Cyber Essentials** encodes the security update management control of the Cyber Essentials requirements for IT infrastructure, version 3.2 (April 2025), published by the National Cyber Security Centre. The scheme asks that updates fixing vulnerabilities the vendor rates critical or high risk, or with a CVSS v3 base score of 7 or above, are applied within 14 days of release, and that software the vendor no longer supports is removed from scope. The preset installs one SLA configuration named UK Cyber Essentials with 14 day Critical and High windows, enforced, and Medium and Low left at your default day counts and not enforced. It adds one disabled scan cadence policy for a scan at least every 30 days, and two checks: unsupported components present, and active Critical and High findings older than 14 days. Review how each of your scanners maps severity onto the CVSS threshold before relying on the window.

**Australian Essential Eight** encodes the patch applications and patch operating systems strategies of the Essential Eight Maturity Model, November 2023, published by the Australian Signals Directorate. The model sets windows by asset class and by whether an exploit exists rather than by severity, so the preset uses severity as a proxy and says so in its notes. It ships three variants, one per maturity level, and you pick the level you are targeting instead of editing numbers. Maturity Level One installs an SLA configuration with two week Critical and High windows and leaves Medium and Low at your defaults. Maturity Levels Two and Three add a one month window for Medium and Low. All three install disabled scan cadence policies at the level's frequency: daily for internet-facing services, fortnightly or weekly for applications that handle untrusted content, and fortnightly for other assets from Level Two. The 48 hour rule lives in the response policy: internet-facing services when an exploit exists or the vendor rates the vulnerability critical, and at Level Three the same rule for applications that handle untrusted content. Tag those applications, such as browsers, office suites, email clients, PDF readers and security products, with the handles-untrusted-content tag so the cadence policy and the check for them apply.

## Plan, then apply

Applying is a two step process, and nothing is written until you have seen the plan.

1. Open Settings, then Framework Presets, and choose Apply on a preset. For the Essential Eight, pick the maturity level first.
2. Choose Preview plan. The plan lists every item the preset contains and what applying would do to it: create it, update it, leave it because it conflicts with something already there, or skip it and why. An update or a conflict shows the current and the proposed values side by side.
3. Confirm that you have reviewed the plan, then choose Apply this plan. The plan runs as one transaction: either every item in it is applied or none is.

An item is a conflict when an SLA configuration with the same name already exists with different values and was not created by this preset. The plan shows both sets of values, the configuration is left untouched, and the application is recorded as partially applied. Compare the two and decide by hand. An item this preset created earlier is updated rather than treated as a conflict, so applying a preset again after a hand edit restores its numbers.

If something changes between the preview and the apply, for example a configuration with the same name appears, DefectDojo refuses to apply and asks you to build the plan again.

## Why applying does not reassign assets

Applying a preset creates SLA configurations and tells you which ones it created. It never moves an asset onto one of them. Changing every deadline in a live instance is a decision for the people who own those assets, so after applying, point the assets that should follow the scheme at the new SLA configuration from each asset's edit page, or through the criticality to SLA mapping if you use it.

## Revert

Revert undoes an application. Configurations the application created are deleted, and configurations it updated are restored to the values they had before. Two kinds of row are listed and left alone: a configuration someone edited by hand after it was applied, and a configuration an asset now points at. The history shows what was reverted and what was left, with the reason.

## Drift

Once a week DefectDojo compares each applied preset against the current settings. When an SLA configuration a preset installed no longer matches what the preset wrote, for example because someone changed a day count by hand, the application is marked as drifted and the field that moved is named in its history entry. The Framework Presets page shows a single banner while any applied preset has drifted. Drift is a state, not an event: no notification is sent.

## Versions

A preset records the publication version it encodes. When a scheme is revised, DefectDojo ships the revision as a new preset that supersedes the old one rather than changing the old preset in place, so a configuration you applied never changes underneath you at upgrade time. The gallery shows which preset replaces a superseded one, and previewing the newer version shows the differences.

## Export and import

Any preset can be exported as a JSON file and imported into another instance, which is how a configuration moves from a staging instance to production, and how a customer specific bundle can be delivered without a screen share. An imported preset is a custom preset: it can be edited or deleted, and its key must not already exist on the receiving instance. Bundled presets are read only; export one and import the copy under a new key to customise it.

## API

The public API exposes the same operations under `/api/v2/`. A preset is planned with `POST /api/v2/framework_presets/{id}/plan/`, which returns the plan as an application record, and applied with `POST /api/v2/framework_presets/{id}/apply/`, passing the id of that record. Checks are answered by `GET /api/v2/framework_presets/{id}/checks/`. The history is at `/api/v2/preset_applications/`, with `POST /api/v2/preset_applications/{id}/revert/` to revert one. Export is `GET /api/v2/framework_presets/{id}/export/` and import is `POST /api/v2/framework_presets/import/`. Reading needs the view permission on SLA configurations; planning, applying and importing need the add and change permissions; reverting needs the delete permission as well.
