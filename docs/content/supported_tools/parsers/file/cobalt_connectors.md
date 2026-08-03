---
title: "Cobalt.io (Connectors Import)"
toc_hide: true
---

Import a [Cobalt.io](https://www.cobalt.io/) findings export in the connector's JSON shape.

DefectDojo also ships a **`cobalt`** parser for Cobalt's **CSV** export, under the scan type
`Cobalt.io Scan`. That one is unchanged and still the right choice for a CSV. This parser exists for the
connector's own scan type and JSON shape, so a customer who cannot grant Cobalt API credentials can
upload the same data the DefectDojo Pro Cobalt.io connector syncs.

### File Types

JSON, from Cobalt's findings endpoint. Each finding is nested under `resource`, and the human-facing
deep link sits **outside** it at `links.ui.url`:

```json
{"data": [{"resource": {"id": "...", "title": "..."}, "links": {"ui": {"url": "..."}}}]}
```

Reading the entry directly would find no fields; reading only the resource would lose the link, which
is the only route back to the pentest report. An already-flattened export is accepted too.

### Pentest state becomes the DefectDojo state

Cobalt findings move through a pentest workflow, and the connector translates each state:

| Cobalt `state` | Active? | Also flagged |
| --- | --- | --- |
| `new` | yes | *not verified* |
| `triaging` | yes | *not verified* |
| `need_fix` | yes | verified |
| `check_fix` | yes | verified |
| `carried_over` | yes | verified |
| `duplicate` | **yes** | duplicate |
| `wont_fix` | **yes** | risk accepted |
| `valid_fix` | no | mitigated |
| `invalid` | no | false positive |
| `out_of_scope` | no | out of scope |

Only fixed, invalid and out-of-scope close a finding. A **duplicate or an accepted risk stays active** —
the connector flags them without closing them, since both may still need tracking.

`new` and `triaging` are the only unverified states: Cobalt moves a finding past them once the pentest
team has confirmed it.

**A state Cobalt adds later is not imported.** Every documented state is in the importable set, so an
unknown one means the API changed — skipping it is safer than guessing which DefectDojo state it maps
to.

### Severity

Cobalt's own severity word: `critical`→Critical, `high`→High, `medium`→Medium, `low`→Low, and anything
unrecognised→Info. Cobalt's own severity justification text is imported alongside it.

### Dates come from the log, not `created_at`

Cobalt can **carry a finding over** from an earlier pentest, and in that case `created_at` is the
carry-over date rather than when the finding was actually found. The date therefore comes from the
timestamp of the `created` entry in the finding's log, falling back to `created_at` only when there is
no log. `last_status_update` is the latest timestamp anywhere in the log.

### Fields worth noting

- **CVSS** — Cobalt can report v2 and v3 side by side, so the **first entry whose version starts with
  `3`** is used. Taking whichever came first would put a v2 vector in the v3 column.
- **Impact and likelihood** are numeric scores, and **zero is a real score** — reported rather than
  silently omitted as a falsy value.
- **Title** — trimmed to DefectDojo's 511-character column, cut at the last space so a word is not
  split mid-way.
- **Steps to reproduce** carries Cobalt's proof of concept.
- **Endpoints** — the pentest's affected targets.

### Scan type and deduplication

The scan type is **`Cobalt.io - Connectors Import`** — identical to the string the Cobalt.io connector
reports, and distinct from the CSV parser's `Cobalt.io Scan`. A test asserts both, so the two parsers
cannot start shadowing each other.

Finding ids are stable, so deduplication uses the plain `hash_code` algorithm over
`unique_id_from_tool` alone.

### Sample Scan Data

Sample scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/cobalt_connectors).

The samples are constructed from Cobalt's documented findings schema and cover every row of the state
table above plus an unknown state, a carried-over finding whose log predates `created_at`, a v2 CVSS
entry listed before the v3 one, and zero-valued impact and likelihood. Hosts and identifiers are
generic placeholders.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
