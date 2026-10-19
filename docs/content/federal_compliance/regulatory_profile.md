---
title: "Regulatory Profile"
description: "Record the CRA, DORA and NIS2 facts for an Asset: critical or important function, CRA product class, support period, and where vulnerability reports go"
weight: 10
audience: pro
---

EU regimes such as the Cyber Resilience Act (CRA), the Digital Operational Resilience Act (DORA)
and NIS2 start with the same few questions about a product. Does it support a critical or
important function? Which CRA product class is it in? How long is it supported? Where does a
researcher send a vulnerability report? The regulatory profile is where an Asset records those
answers, so other DefectDojo Pro features can read them.

The profile records facts that you supply. DefectDojo does not decide whether a regulation
applies to an Asset, does not classify the product for you, and does not establish compliance
with any regime. Confirm applicability and classification with qualified legal and compliance
reviewers.

## Enable the Regulatory Profile

The Regulatory Profile is released behind the **Regulatory Profile** feature flag, which is in
beta, experimental, and off by default. An administrator turns it on per instance from
[Feature Flags](/admin/feature_flags/pro__feature_flags/).

The same profile also holds an Asset's PCI DSS scope facts, so the **PCI DSS** flag opens it as
well. With only **Regulatory Profile** on, the Asset page shows and saves the CRA and DORA
fields, while PCI DSS scope confirmation and the scope inventory export stay closed. See
[PCI DSS Scope and Patch Clocks](/asset_modelling/engagements_tests/pro__pci_dss_scope/).

## Where to edit it

With the flag on, the Asset page shows a **Regulatory** card. Fill in the fields and select
**Submit**. An Asset has at most one profile. It does not exist until the first save, and
until then every field reads as its default.

You need permission to edit the Asset to change its profile. A user who can only view the
Asset sees the card read-only.

## Fields

| Field on the card | API field | Values | What it records |
|---|---|---|---|
| **Supports a Critical or Important Function** | `supports_critical_or_important_function` | `true` or `false`, default `false` | Whether the Asset supports a critical or important function, per DORA Article 8(1). Scan cadence policies read it to apply a weekly scanning expectation. |
| **CRA Product Class** | `cra_product_class` | See the table below, default `not_applicable` | The product's class under the CRA (Article 7, Annexes III and IV), which sets its conformity assessment route. |
| **Support Period End** | `support_period_end` | A date (`YYYY-MM-DD`), optional | The end of the product's support period, per CRA Article 13(8). |
| **Security Contact** | `security_contact` | Text up to 255 characters, optional | An email address or URL for reporting vulnerabilities, per CRA Annex I Part II point 6. |
| **Disclosure Policy URL** | `cvd_policy_url` | A valid URL up to 512 characters, optional | A link to the product's coordinated vulnerability disclosure policy, per CRA Annex I Part II point 5. |
| **SLA Locked** | `sla_locked` | `true` or `false`, default `false` | Keeps the Asset out of criticality-driven SLA assignment, so it keeps its current SLA configuration. |
| **Notes** | `notes` | Free text, optional | Notes for the assessor. |

The **CRA Product Class** choices:

| Label | API value |
|---|---|
| Not Applicable | `not_applicable` |
| Default | `default` |
| Important, Class I | `important_class_1` |
| Important, Class II | `important_class_2` |
| Critical | `critical` |

PSIRT treats any value other than **Not Applicable** as in scope for the CRA (see below).

## What reads the profile

- **Scan cadence policies.** A policy with **Only Critical or Important Functions** checked narrows its scope to
  Assets whose profile has **Supports a Critical or Important Function** set. An Asset with no
  profile counts as not critical. See [Scan cadence policies](/sensei/scan_cadence_policies/).
- **CRA Article 14 suggestions in PSIRT.** A PSIRT case suggests a CRA Article 14 early warning
  when it carries a feed item known to be exploited and at least one matched component belongs
  to an Asset whose **CRA Product Class** is not **Not Applicable**. The suggestion appears as a
  banner on the case and on its advisory. It never starts a report; a person does. DefectDojo
  records when the suggestion first appeared to someone.
- **CRA Article 14 Reports.** The **CRA Article 14 Reports** page and its navigation entry
  appear when this flag is on. The page tracks the statutory deadlines for each report.
  Submission to the reporting platform is done by a person.
- **Regulatory Scope dashboard widget.** The widget can count, per regulation, the in-scope
  Assets whose **Support Period End** has passed or falls within the next 90 days.
- **Criticality SLA mappings.** A mapping that moves Assets in a business-criticality band onto
  an SLA configuration skips any Asset with **SLA Locked** set.
- **FDA cyber device evidence pack.** The disclosure route obligation reads **Security Contact**
  and **Disclosure Policy URL**. See
  [FDA Cyber Device Evidence Pack](../fda_cyber_device_pack/).

The CRA and DORA [evidence packs](../eu_evidence_packs/) do not read **Supports a Critical or
Important Function** today. Their scan cadence obligation uses the Asset's business criticality
as a proxy for the designation and says so in the evidence.

## API

The profile is available at `/api/v2/regulatory_profiles/`, with the usual list, retrieve,
create, update and delete operations. Filter by Asset with `?product=<id>`. Reading needs view
permission on the Asset and writing needs edit permission. When neither the Regulatory Profile
nor the PCI DSS flag is on, the endpoint answers `403` with "Regulatory profiles are not
enabled."

A profile is tied to one Asset when it is created. The `product` field cannot change on update.

```bash
# Create the profile for Asset 42
curl -X POST "https://defectdojo.example.com/api/v2/regulatory_profiles/" \
  -H "Authorization: Token <your API token>" \
  -H "Content-Type: application/json" \
  -d '{
        "product": 42,
        "supports_critical_or_important_function": true,
        "cra_product_class": "important_class_1",
        "support_period_end": "2031-12-31",
        "security_contact": "security@example.com",
        "cvd_policy_url": "https://example.com/vulnerability-disclosure"
      }'
```

The response also carries the PCI DSS fields and the cyber device fields that share the profile.
On a `PATCH`, send only the fields you want to change.
