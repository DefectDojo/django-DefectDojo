---
title: "Custom Fields"
description: "Define typed custom fields per record type, fill them in on the forms and on each record, and turn them on as typed table columns"
audience: pro
weight: 7
---

**Custom Fields** let you attach your own structured data to DefectDojo records. Unlike the earlier
free-form key/value metadata, custom fields are **typed and defined up front**: an administrator
defines each field once (a label, a key, and a data type), and everyone else fills in a value of that
type on the records they work with.

Custom Fields is turned on per instance from the **Custom Fields** row on the **Settings > Feature Flags** page. Enabling
it is one-way, and it replaces the earlier metadata feature: once on, DefectDojo reads and writes
custom fields everywhere metadata was used, so existing metadata values are no longer shown until you
convert them. Converting your existing metadata is a separate, optional step you run when you are ready
(see [Moving from the earlier metadata](#moving-from-the-earlier-metadata)). Until the feature is
enabled, DefectDojo behaves as it did before: metadata stays free-form and the settings page, record
editors, and columns described below are not shown.

Custom fields are available on six record types:

- **Organizations**
- **Assets**
- **Engagements**
- **Tests**
- **Findings**
- **Risk Acceptances**

## Defining fields

Custom fields are definitions-first: a value can only be filled in for a field that has been defined.
Superusers define fields under **Settings > Configuration > Custom Fields**. Pick a record type, then
add the fields that apply to it. Each definition has:

- **Record type**: which of the six record types the field applies to. A field defined for Findings
  is offered only on Findings.
- **Label**: the human-readable name shown wherever the field is displayed or filled in: on the
  record, in the editor, and as the table column header.
- **Name**: a URL-safe key used in URLs, column identifiers, and filter and sort parameters. It may
  contain only lowercase letters, digits, and underscores (for example `cost_center`). The name is
  suggested automatically from the label and can be edited before you save.
- **Data type**: one of seven types, which fixes how the value is entered, validated, filtered, and
  sorted.
- **Required**: whether a value has to be filled in on the record type's create and edit forms. A
  required field always appears on those forms and cannot be hidden from them.
- **Allow Other** (Single Select and Multi Select only): whether the field also offers an **Other**
  choice that takes a typed value. See [The Other choice](#the-other-choice).
- **Formula** (Integer and Decimal fields): fills the value in from the record's numbers instead of
  by hand. See [Computed fields](#computed-fields).

### Data types

| Data type | Entered as | Example |
|-----------|------------|---------|
| **Text** | A free-text box | `Payments platform` |
| **Integer** | A whole number | `42` |
| **Decimal** | A number with decimals | `3.5` |
| **Date** | A date picker | `2026-08-17` |
| **Boolean** | Yes / No | `Yes` |
| **Single Select** | One choice from a list you define | `Tier 1` |
| **Multi Select** | Any number of choices from a list you define | `PCI, SOC 2` |

For **Single Select** and **Multi Select**, you also supply the list of options when you define the
field. You can change a field's data type later; existing values are re-evaluated against the new
type, and any that no longer fit stop being shown as typed values.

### The Other choice

A select field's options do not always cover every answer. Turn on **Allow Other** for the field
(when you add it, or with the **Other** checkbox in its row) and its dropdown gains an **Other**
choice after the options you defined. Choosing **Other** shows a text box, and what you type there is
saved as the field's value:

- On a **Single Select** field, the typed text is the value, in place of an option.
- On a **Multi Select** field, the typed text is saved alongside any options you picked. Each record
  holds at most one Other value.

Options match exactly, letter case included: typing `major release` when the field has a `Major
Release` option saves an Other value, not that option. The typed value is shown, filtered and sorted
like any other value of the field. When you open a record whose value is not one of the options, the
editor shows **Other** chosen with the text filled in. Through the API, write the typed text as the
value itself (`value` for a Single Select field, one entry of `value_options` for a Multi Select
field).

**Allow Other** cannot be turned off while any record holds an Other value: the change is refused and
says how many records hold one. Change those records to one of the defined options first, or add their
typed text to the field's options, which makes it an ordinary option. It is also refused while an
enabled rule sets the field to a value outside its options, and the message names those rules: update
or disable them first.

## Computed fields

Any Integer or Decimal custom field can be **computed**: DefectDojo fills its value in with a
formula, and nobody types it. A typical use is a health score for each Asset, or a weighted risk on
each Finding. Give the field a formula when you add it, or type one into the **Options or Formula**
column of its row; clearing the formula makes the field an ordinary one again. Because a formula
replaces every value already entered in the field, DefectDojo asks before an existing field becomes
computed, and again before a computed field goes back to being entered by hand (its values stay as
last computed). **Insert Number** beside the formula lists every number it can read.

A formula reads the record's own numbers:

- **Built-in numbers**: `fields.<name>`. On a Finding: `cwe`, `cvssv3_score`, `cvssv4_score`,
  `epss_score`, `epss_percentile`, `line`, `occurrences`, `scanner_confidence`, `priority`,
  `risk_score`, `threat_score`, `threat_ladder_rung`, `pain_rating` and `reachability_confidence`. On
  an Asset: `grade`, `user_records`, `revenue`, `exposure_confidence` and `patch_cycle_days`. On a
  Test: `percent_complete`.
- **Number custom fields**: `custom_fields.<name>` for the record's Integer and Decimal fields,
  computed ones included.
- **Finding counts** (on an Organization, Asset, Engagement, Test or Risk Acceptance):
  `findings.active.total`, `findings.active.risk.urgent` (and `needs_action`, `medium`, `low`,
  `unscored`), `findings.active.severity.critical` (and `high`, `medium`, `low`, `info`), and the
  same under `findings.open` for open Findings (active, and not a duplicate, false positive, out of
  scope, risk accepted or mitigated).
- **Finding aggregates** (on the same records): `findings.<active|open>.<sum|avg|min|max>.` followed
  by any Finding number, built-in or custom. For example `findings.open.max.fields.epss_score` is the
  highest EPSS score among the record's open Findings, and `findings.active.sum.custom_fields.cost`
  adds up a Finding custom field. A sum over no Findings is 0; an average, lowest or highest over none
  is missing.

It combines them with `+ - * /`, parentheses, comparisons, `and`, `or`, `not`, and the functions
`min`, `max`, `abs`, `round`, `div(a, b, if_zero)`, `coalesce` and `if(test, a, b)`. For example, a
score from 100 down that weighs each active Finding by its priority band:

```
100 * (1 - div(10 * findings.active.risk.urgent + 5 * findings.active.risk.needs_action
  + 2 * findings.active.risk.medium + findings.active.risk.low, 10 * findings.active.total, 0))
```

### Computed fields that read each other

A computed field can read another computed field, on the same record or, through an aggregate, on its
Findings: a computed `weighted_risk` on each Finding can feed an Asset's
`findings.active.sum.custom_fields.weighted_risk`. DefectDojo recomputes them in order, so a field is
always written before anything that reads it. A formula that would make fields read each other in a
loop is refused when it is saved, and the message names the loop. A field that a computed formula
reads cannot be deleted, or changed to a type other than Integer or Decimal, until those formulas
stop reading it; the message names them.

### When values are recomputed

- **After Findings change.** Saving or deleting a Finding (including an import) recomputes, shortly
  afterwards, the Finding's own computed fields and every computed field on its Asset, Organization,
  Engagements, Tests and the Risk Acceptances on its Engagements.
- **After an input changes.** Changing a custom field value that a computed formula reads (by hand,
  through the API or from a rule) recomputes that record, and a Finding's value recomputes its Asset.
  Saving an Asset or a Test recomputes it when a formula reads its built-in numbers.
- **When the formula changes**, the field and every computed field that reads it are recomputed for
  every record at once.
- **Every hour**, every computed field is recomputed in full. That catches changes made without saving
  each record, such as bulk updates, priority recalculations and records moving between Assets. A
  sweep still running when the next hour comes is never overlapped; the next one is skipped.

When a computed field gets a new value, the Triage Engine hears it the same way as a rule writing that
field. On an Asset, a rule triggered [On Asset Event](/automation/triage_engine/node_reference/#on-asset-event)
for updates sees `custom_fields.<name>` in `ctx.changed_fields`, so an If / Filter node with
`ctx.changed_fields` `contains` `custom_fields.<name>` runs only when that value moves. On a Finding,
it is a Finding update. A recompute that leaves the value unchanged raises no event.

Counts and aggregates include every Finding of the record, whoever is looking, so everyone sees the
same value, as with the Asset grade. An Integer field rounds half away from zero; a Decimal field keeps
up to four decimal places. A record whose formula reads a number it does not have, or divides by zero
with `/`, keeps its previous value: use `div` or `coalesce` to give such a record a value of its own.

A computed value cannot be typed on the record, set through the API, or written by a rule; on the
record and its forms it shows read-only, with its formula. A field cannot be made computed while an
enabled rule writes it (the message names the rules). To compute a value only on some records, or on a
schedule of your own, use a [rule with a formula](/automation/triage_engine/node_reference/#formulas)
instead.

## Filling in values

Once fields are defined for a record type, fill them in from the record's **⋮ (kebab) menu → Custom
Fields**. This opens a typed editor that lists every field defined for that record type, with the
right input for each data type: a date picker for dates, a dropdown for select fields, a Yes/No
toggle for booleans, and so on. Values are validated against the field's type when you save. The
editor is available on all six record types: Organizations, Assets, Engagements, Tests, Findings, and
Risk Acceptances.

If no fields are defined for the record type yet, the editor says so, and an administrator can define
them under **Settings > Configuration > Custom Fields**.

## Custom fields on the create and edit forms

Custom fields also appear on the create and edit forms for their record type, so a value can be filled
in while the record is being created rather than only afterwards. Each field uses the same input as the
typed editor, and is validated the same way when the form is submitted.

By default custom fields appear at the end of the **Optional Fields** section. An administrator can
change that for each form under **Settings > UI Defaults > Form Configuration**, where every custom
field is listed alongside the built-in fields and can be moved into the main body of the form, hidden,
made required for that form, or reordered. See
[Configuring Forms](../../navigation/pro__form_configuration/) for how those controls work.

A field marked **Required** when it was defined is required on every form for its record type: the form
cannot be submitted until it has a value, and it cannot be hidden. Form Configuration can additionally
require a field that was not defined as required, which applies to that one form.

Custom field values are stored separately from the record itself, so they are saved immediately after
the record is. If a value cannot be saved, the record is still created or updated and a message names
the fields that were not saved.

## Showing custom fields on a record's page

Custom fields are ordinary page fields, so you can show them on a record's page through its layout
controls. Add a **Simple Table** widget and include the custom fields you want, or add a
**single-field** widget bound to one custom field. Each shows the saved, typed value for the record.
Custom fields are not part of the default layout; you place them where you want them.

## Custom fields as table columns

Every defined custom field is available as an **opt-in column** on that record type's list table. The
columns are hidden by default; turn them on from the table's column picker. Each column filters and
sorts according to its data type: numbers filter by range, dates by before or after, booleans by
Yes/No, text by contains, and select fields by their options. Columns, filters, and the sort
parameter use the field's **Name**, so sorting a list by a `cost_center` field appears in the URL as
`o=cost_center`.

A select field that allows Other also gets a **<Label>: Other** filter (Yes or No), which finds the
records whose value is a typed Other value, or the records whose value is not. Its parameter is the
field's Name followed by `_other`, for example `reason_other=true`.

## Moving from the earlier metadata

Enabling the feature does not move any data on its own: it switches Findings and Assets over to the
typed store, so metadata you entered before is no longer shown until you convert it. When you are ready,
click **Convert** under **Custom Fields** on the **Settings > Feature Flags** page. It copies existing
Finding and Asset metadata into typed fields with a best-effort data type inferred from the values, runs
in the background with a progress bar you can watch (and cancel), and is non-destructive: the original
metadata rows are left in place. The conversion is safe to run again: it never duplicates, and a re-run
finishes one that was cancelled or interrupted.

Once the feature is enabled, the legacy metadata endpoints are disabled for findings and assets: the
`/api/v2/findings/{id}/metadata/` endpoint and the flat `/api/v2/metadata/` endpoint return **404** for
those owners, and the `finding_meta` / `product_meta` / `asset_meta` fields on the v2 API return empty.
Read and write custom field values through the **`/api/v2/custom_fields/values/`** endpoint instead, and
manage the field definitions through **`/api/v2/custom_fields/definitions/`**. Both use standard API-token
authentication (the same `Authorization: Token <key>` header as the rest of the API) and are listed in the
v2 Swagger UI under the **Custom Fields** tag. You can read a value wherever you can view its object and
write one wherever you can edit it, while managing definitions requires the global Custom Field management
permission. Endpoint and Location metadata is unaffected and still lives on the metadata endpoints.

To list the custom field values on one object, filter the values endpoint by that object's id:

| Object | Query parameter |
|--------|-----------------|
| Asset | `?asset={id}` (or `?product={id}`) |
| Organization | `?organization={id}` (or `?product_type={id}`) |
| Finding | `?finding={id}` |
| Engagement | `?engagement={id}` |
| Test | `?test={id}` |
| Risk Acceptance | `?risk_acceptance={id}` |

For example, `GET /api/v2/custom_fields/values/?asset=12` returns the custom field values on asset 12. The
response is paginated like the rest of the API, so follow `next` (or pass `limit` and `offset`) when an object
has more values than one page holds. Filters combine, so a request only returns values that match all of them,
and values on an object you cannot view are never returned. An id that is not a whole number returns a **400**.

To list the fields that apply to one object type, filter the definitions endpoint by `entity_type` (`finding`,
`asset`, `organization`, `engagement`, `test` or `risk_acceptance`; `product` and `product_type` also work),
for example `/api/v2/custom_fields/definitions/?entity_type=asset`. An unknown type returns a **400**.

Metadata on **Endpoints** and **Locations** is a separate feature and is unchanged: it stays as
free-form key/value metadata and is not part of the typed custom fields subsystem.
