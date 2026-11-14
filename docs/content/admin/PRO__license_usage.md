---
title: "Processed Findings and the Usage Export"
description: "How DefectDojo Pro counts Processed Findings, where the count appears, and how a self-hosted instance exports it"
weight: 11
audience: pro
draft: false
---

Some DefectDojo Pro licenses measure **Processed Findings**: the findings your tools send to DefectDojo for processing. This page explains what that count includes, where you can see it, and how a self-hosted instance writes it to a file with the `usage_export` command.

Processed Findings is a **DefectDojo Pro** feature. It applies only to a license that measures Processed Findings. A license that measures stored findings (Total Findings) keeps counting the way it always has.

## What counts

Processed Findings counts what each import and reimport submitted, at the moment it was processed:

- **Every finding in every import and reimport counts.** It is counted once per submission, so a finding that two reimports both contain counts twice. Findings that the minimum severity setting filters out do not count.
- **It is counted before deduplication.** The number is what your tools sent, not how many findings DefectDojo kept after matching them against existing ones. Closing, reopening or deleting findings later does not change it.
- **Previews never count.** Running an import or reimport as a preview processes nothing, so it adds nothing.
- **Failed imports never count.** An import or reimport that ends in an error adds nothing, even when the file was read before the error.
- **Production only.** Imports into the [sandbox](/admin/sandbox/pro__sandbox/) do not count.

A license that measures Processed Findings counts them from its start date. When a new license is applied, the count starts again from the new license's start date.

## Where to see it

Go to **Settings > License & Support > License Manager**. The usage card for this license reads **Processed Findings** and shows the count, the limit and the percentage used. The **Audit Usage** section lists Processed Findings beside any other counted item, such as users, and shows each one's total on its own line. Because Processed Findings are submissions rather than stored records, there is no list of them to open.

The same number appears in the **License Usage** button on the All Findings page and in the License Usage tile on a dashboard.

## Exporting usage from a self-hosted instance

A self-hosted instance does not report its usage to DefectDojo, so when DefectDojo asks for a usage report you create it with the `usage_export` management command and send the file you get.

Run it in the DefectDojo application container, with the first and last day of the period you were asked for:

```bash
python manage.py usage_export --from 2027-01-01 --to 2027-03-31 --output usage.json
```

- `--from` and `--to` are UTC calendar days in `YYYY-MM-DD` form, and both days are included.
- A single export covers at most 400 days. For a longer period, run it more than once.
- Without `--output`, the report is written to standard output instead of a file.

The command refuses a date it cannot read, a `--from` day after the `--to` day, and a period longer than 400 days, and says which one it was.

### What the file contains

The file is JSON. It holds counts and license dates only: no findings, assets, users or scan contents.

```json
{
  "from": "2027-01-01",
  "to": "2027-01-03",
  "days": [
    { "date": "2027-01-01", "processed": 1250 },
    { "date": "2027-01-02", "processed": 0 },
    { "date": "2027-01-03", "processed": 830 }
  ],
  "total": 2080,
  "license": {
    "license_id": "5d41402abc4b2a76b9719d911017c592...",
    "license_id_method": "sha256, lowercase hex, of the UTF-8 bytes of the plaintext license text ...",
    "licensed_to": "Example Corp",
    "generated_at": "2026-12-15T00:00:00Z",
    "not_before": "2026-12-15T00:00:00Z",
    "not_after": "2027-12-14T00:00:00Z"
  }
}
```

- `days` lists every UTC day in the period, including days with nothing processed (`0`), so a quiet day is never confused with a missing one.
- `total` is the sum of the days.
- `license` says which license the usage was counted under. `license_id` is a SHA-256 fingerprint of the license installed on the instance, and `license_id_method` states exactly how it is computed. The fingerprint identifies the license without containing any of it.
