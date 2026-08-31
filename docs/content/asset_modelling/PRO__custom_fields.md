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

Custom Fields is turned on per instance from **Settings → Feature Flags → Custom Fields**. Enabling
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
Superusers define fields under **Settings → Configuration → Custom Fields**. Pick a record type, then
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

## Filling in values

Once fields are defined for a record type, fill them in from the record's **⋮ (kebab) menu → Custom
Fields**. This opens a typed editor that lists every field defined for that record type, with the
right input for each data type: a date picker for dates, a dropdown for select fields, a Yes/No
toggle for booleans, and so on. Values are validated against the field's type when you save. The
editor is available on all six record types: Organizations, Assets, Engagements, Tests, Findings, and
Risk Acceptances.

If no fields are defined for the record type yet, the editor says so, and an administrator can define
them under **Settings → Configuration → Custom Fields**.

## Custom fields on the create and edit forms

Custom fields also appear on the create and edit forms for their record type, so a value can be filled
in while the record is being created rather than only afterwards. Each field uses the same input as the
typed editor, and is validated the same way when the form is submitted.

By default custom fields appear at the end of the **Optional Fields** section. An administrator can
change that for each form under **Settings → UI Defaults → Form Configuration**, where every custom
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

## Moving from the earlier metadata

Enabling the feature does not move any data on its own: it switches Findings and Assets over to the
typed store, so metadata you entered before is no longer shown until you convert it. When you are ready,
click **Convert** under **Custom Fields** on the **Settings → Feature Flags** page. It copies existing
Finding and Asset metadata into typed fields with a best-effort data type inferred from the values, runs
in the background with a progress bar you can watch (and cancel), and is non-destructive: the original
metadata rows are left in place. The conversion is safe to run again: it never duplicates, and a re-run
finishes one that was cancelled or interrupted.

Once the feature is enabled, the legacy metadata endpoints are disabled for findings and assets: the
`/api/v2/findings/{id}/metadata/` endpoint and the flat `/api/v2/metadata/` endpoint return **404** for
those owners, and the `finding_meta` / `product_meta` / `asset_meta` fields on the v2 API return empty.
Read and write custom field values through the `/api/vue/custom_field_values/` API instead. Endpoint and
Location metadata is unaffected and still lives on the metadata endpoints.

Metadata on **Endpoints** and **Locations** is a separate feature and is unchanged: it stays as
free-form key/value metadata and is not part of the typed custom fields subsystem.
