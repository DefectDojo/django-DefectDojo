---
title: "Advisory Feeds"
description: "Enable security advisory feeds for PSIRT: the shipped catalog, terms acceptance, and feed health."
draft: false
weight: 2
pro-feature: true
---

PSIRT's advisory feeds bring publisher security advisories (CISA, NVD, Red Hat,
Debian, EUVD, and more) directly into your DefectDojo Pro instance, where they
are matched against your software inventory to answer one question: **am I
vulnerable to this new advisory?**

Feeds are part of the platform-native PSIRT module (beta). Two prerequisites:

- The **PSIRT** feature flag (Settings → Feature Flags). It requires the
  **Locations** feature, because matching runs against the SBOM-derived
  dependency inventory.
- The **PSIRT Advisory Engine** entitlement on your license.

## Your installation fetches its own data

Every feed is polled by **your** DefectDojo instance, from your network, under
your organization's own relationship with each publisher. DefectDojo operates
no shared feed service and redistributes no publisher content. This is a
deliberate design: you fetch, you store, you use.

## The shipped catalog

PSIRT ships a curated catalog of 20 advisory sources. Every source arrives
**disabled** — nothing polls until a person in your organization reviews and
accepts that source's terms.

Each source shows a clearance state:

- **Cleared** — the publisher's terms permit this use; you can enable it after
  accepting the terms.
- **Pending clearance** — DefectDojo is completing a licensing agreement with
  the publisher, or the publisher's terms are under legal review. These
  sources are visible but cannot be enabled yet; each one explains what
  unlocks it. Sources unlock in product updates as clearances land.

A few cleared sources are marked **transport coming soon**: their re-pointed,
cleanly-licensed channels (for example the Linux kernel CVE git repository)
need a connector that arrives in an upcoming update.

## Enabling a feed

Enabling is a recorded transaction, not a toggle:

1. Open **PSIRT → Feeds** and choose a source.
2. Review the terms panel: the publisher's license, the attribution DefectDojo
   will render, and any additional notices.
3. Accept the terms. Your acceptance (who, when, and the exact terms text) is
   recorded in an append-only ledger that retention jobs never touch.
4. If the source needs a credential (for example your own NVD API key), enter
   it during the same step. Credentials are encrypted at rest and are never
   echoed back by the API or the UI.
5. Polling begins on the source's schedule (every 6, 12, or 24 hours,
   depending on the source).

If a publisher's terms change in a later release, the feed keeps polling, but
the Feeds page asks for a fresh acceptance of the new text.

## Custom feeds

You can add your own RSS/Atom sources. The same acceptance step applies — for
a source DefectDojo has not vetted, your acceptance records that your
organization takes responsibility for its terms.

## Feed health

Each source shows a health chip driven by its recent poll outcomes: healthy,
degraded, failing, never polled, or off — alongside the last successful poll
time and the most recent error when there is one. Health reflects poll
reliability, not how many advisories a publisher happened to issue.

## Attribution

Wherever advisory content appears — in PSIRT screens and in findings exported
from advisories — DefectDojo renders the credit each publisher requires,
including the MITRE CVE designation and license notice for CVE data and
NIST's non-endorsement disclaimer for NVD-derived data.
