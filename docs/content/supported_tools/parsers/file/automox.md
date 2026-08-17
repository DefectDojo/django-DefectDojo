---
title: "Automox"
toc_hide: true
---

Import an [Automox](https://www.automox.com/) export of awaiting (missing) patches.

This exists for organisations that cannot grant Automox API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Automox connector pulls the
same data over the API; this parser accepts the same data as a file.

### File Types

JSON. Each missing patch is one finding.

Automox reports the **patch and its device from two different endpoints**, so an export carries both
lists and they are joined on the package's `server_id`:

```json
{
  "devices":  [ { "id": 1001, "name": "generic-host-01", "os_family": "Windows" } ],
  "packages": [ { "id": 900001, "server_id": 1001, "name": "example-runtime" } ]
}
```

The devices list may be named `servers` instead, matching the endpoint it comes from. The packages
list may be named `packages`, `data` or `results` — or the file may be a **bare array of packages**,
which is exactly what the packages endpoint returns.

A package whose device is not in the export is **still a finding**; the device-derived lines are
simply absent. The connector's device lookup is a map read that can miss, and it converts anyway —
dropping the finding would lose a real missing patch because the device list did not travel with it.

A row with **no usable `id` is dropped**: the id is the whole identity, and every row without one
would collapse onto `automox-0`. Automox's own decoder rejects the entire page when an id is not
numeric; dropping the single row keeps the rest of the export importable.

Numbers may arrive **quoted** (`"id": "900002"`), for ids and scores alike, because Automox's own
decoder accepts either. A `cve_score` that is not a number becomes `0.0` rather than failing the
import, matching the connector's decoder.

### Severity

| Automox `severity` | Severity |
| --- | --- |
| `critical` | Critical |
| `high` | High |
| `medium` | Medium |
| `low` | Low |
| `none`, `unknown`, `no_known_cves`, absent | Info |

### Fields worth noting

- **Title** is `Missing patch: <display name>`, falling back to the package name and then the id.
- **The component is the package**, not the device, so the same missing patch on two devices hashes
  the same — the package id in the identity is what keeps those two findings apart.
- **The status line** only appears when the patch is available and *not* installed.
- **Timestamps** are Automox's `2006-01-02T15:04:05-0700` form first, then RFC 3339. An unparseable
  one leaves the finding date at the import default rather than dropping the finding.
- **Tags** are the device's OS family and `requires-reboot`. The connector's own comment says the
  severity is tagged too; its code does not, and the code is what is mirrored here.

### Sample Scan Data

Sample Automox scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/automox).

The samples are constructed from Automox's documented device and package responses and cover a
patch with two CVEs, a package whose device is absent, quoted numerics, a non-numeric score, an
already-installed package, a package with no name, an unparseable timestamp, two rows with no usable
id, and a bare packages array with no devices at all. Host and package names are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
