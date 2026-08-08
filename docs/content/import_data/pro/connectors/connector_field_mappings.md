---
title: "Connector Field Mappings"
description: "Change how a Connector's findings map onto DefectDojo fields, including what deduplication uses"
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Connectors are a DefectDojo Pro-only feature.</span>

Each Connector decides how its tool's data becomes a DefectDojo Finding: which value
becomes the Title, which becomes the Description, and so on. Those decisions are built into
the Connector, and until now disagreeing with one meant opening a support request and waiting
for a release.

Connector field mappings let you make that change yourself. You define derivations that are
applied to every incoming finding, for one scan type, before it becomes a Finding.

## What field mappings can and cannot change

This is the first thing to understand, because it decides whether mappings are the right tool
for your problem at all.

A Connector sends DefectDojo **the finding it has already assembled** — Title, Description,
Severity, Component Name, and the rest of the DefectDojo finding fields. It does not send the
original vendor record alongside it.

So field mappings can:

* **Rearrange** — put a value that currently lands in one field into another.
* **Combine** — build one field out of several, such as a composite identifier.
* **Normalise** — strip a varying substring out of a field.

Field mappings **cannot** surface a value the Connector never sent. If the data you want is in
your tool's API response but not in any DefectDojo field, no mapping can reach it; that
requires a change to the Connector itself. Contact
[DefectDojo Support](mailto:support@defectdojo.com) for those.

## Mappings are set per scan type

A mapping applies to a **scan type**, not to an individual Connector record. Every record that
imports under that scan type gets the same mappings.

This is deliberate. Deduplication settings are themselves defined per scan type, so if two
records of the same scan type could carry different mappings, there would be no single answer
to what that scan type's findings are matched on.

## How a mapping is written

A mapping has three parts:

| Part | Meaning |
| --- | --- |
| `target_field` | The DefectDojo finding field to write. Must be a real finding field. |
| `expression` | The value to write. `{field_name}` is replaced with that field's incoming value; anything else is kept literally. |
| `strip_pattern` | Optional regular expression, removed from the result. |

For example, this builds a composite identifier out of four fields the Connector already
sends:

```json
{
  "target_field": "unique_id_from_tool",
  "expression": "{vuln_id_from_tool}|{component_name}|{component_version}|{file_path}"
}
```

And this removes a scan date that the tool folds into every title, so that the same issue does
not look like a new one on each sync:

```json
{
  "target_field": "title",
  "expression": "{title}",
  "strip_pattern": " \\(scanned \\d{4}-\\d{2}-\\d{2}\\)"
}
```

Four behaviours are worth knowing before you write one:

* **Every mapping reads the original finding**, never the output of another mapping. Mappings
  cannot feed into each other, so the result never depends on the order they were saved in.
  Two mappings may not target the same field.
* **A missing field becomes empty rather than an error.** Connectors omit fields that have no
  value, and which fields are missing varies from finding to finding, so a mapping that reads
  an absent field produces an empty string there. It does not fail the sync.
* **Fields holding several values are joined with commas** — vulnerability IDs, for instance —
  rather than rendered as a list.
* **A result is truncated at 4000 characters.**

## Identity-relevant edits versus presentation-only edits

Some fields take part in matching findings against each other and some do not, so DefectDojo
classifies every mapping change before applying it:

* A **presentation-only** change touches a field your deduplication configuration does not
  hash — `mitigation`, `references`, `impact` and similar. It applies with no further
  consequences.
* An **identity-relevant** change touches a field that is hashed, so it changes what a
  finding's identity is built from. Remapping Title, Severity or Description falls here by
  default, as does writing `unique_id_from_tool`.

Which fields are identity-relevant follows **your** deduplication settings for that scan type
under **Enterprise Settings**, not a fixed list, so it tracks any change you make there.

### Do not map a vulnerability ID straight into `unique_id_from_tool`

Some Connectors send `vuln_id_from_tool` but no per-finding identifier, and promoting the one
to the other looks like an easy fix. It is not, and it will lose data.

`vuln_id_from_tool` holds the **vulnerability's** identifier — a CVE or a rule ID — which is
shared by every finding of that vulnerability. Using it as the finding's unique identifier
tells DefectDojo that a hundred separate occurrences are all one finding, and they will
collapse into one. That is worse than having no identifier at all.

Build a **composite** instead, as in the example above. A vulnerability ID together with the
component, its version and the file path is specific to one occurrence, which is what an
identifier has to be.

## Working with mappings through the API

Mappings are managed through the API, and require the **maintainer** global role.

### Create a configuration for a scan type

```
POST /api/vue/connector_field_mappings/
{"scan_type": "Snyk Connectors Import", "transforms": []}
```

Create it empty, then add your mappings with the `PATCH` below. That routes them through
validation and through the identity classification described above, which a create does not
perform.

### Check an edit before making it

Send your proposed mappings to the `impact` endpoint to see how they will be classified,
without applying anything:

```
POST /api/vue/connector_field_mappings/{id}/impact/
{"transforms": [ ... ]}
```

The response tells you whether the edit is identity-relevant, which fields changed, which of
those reach identity, and how many findings already exist under this scan type.

### Make the edit

```
PATCH /api/vue/connector_field_mappings/{id}/
{"transforms": [ ... ], "acknowledge_identity_change": true}
```

The full mapping set is replaced by what you send, so include the mappings you are keeping.
Sending an empty list removes all of them and returns the scan type to what the Connector
sends.

`acknowledge_identity_change` is required **only** for an identity-relevant edit, and the
request is rejected without it. A presentation-only edit does not need it.

An edit is rejected if it targets something that is not a finding field, if an expression reads
a field the payload never carries, if `strip_pattern` is not a valid regular expression, or if
two mappings target the same field.

### View the history

```
GET /api/vue/connector_field_mappings/{id}/revisions/
```

Every mapping set that has been in force is recorded, newest first, with the fields that
changed, whether the edit was identity-relevant, when it happened and who made it.

A configuration cannot be deleted, because the identity generations recorded for its scan type
outlive it. Emptying the mappings is the supported way back.

## What happens to findings you have already imported

An identity-relevant edit opens a **transition window**. While it is open, each sync works out
what its findings would have been under the previous mappings as well as the current ones, and
carries both identities. Findings imported before the edit are matched on the identity they
were stored with, so a reimport updates them rather than closing them and adding duplicates.

Two things to know:

* Only the **immediately previous** identity generation is bridged. If you make two
  identity-relevant edits without a sync in between, findings imported before the first edit
  will not be matched.
* Findings already stored are **not** rewritten, and no recalculation is triggered. Their
  stored fields hold the values the old mappings produced, so recalculating would only
  reproduce the identity they already have. The bridge works on incoming findings, which is
  where the correction can actually be made.

For that reason, make an identity-relevant mapping change and then **sync** — the window is
what carries your existing findings across, and it only helps a sync that happens while it is
open.

## Changing mappings outside the API

Editing a configuration directly in the Django admin, or in a shell, bypasses all of the
above: no revision is recorded, no identity generation is bumped, and no transition window
opens. Findings imported before such a change become unreachable from findings imported after
it. Use the API.

If it has already happened, the `impact` endpoint reports it, as
`unmanaged_identity_change`. Findings imported before that change have no recorded identity for
a later edit's window to bridge from, and a later edit cannot recover them.
