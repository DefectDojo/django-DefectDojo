---
title: "CrowdStrike Falcon Spotlight"
toc_hide: true
---

Import a [CrowdStrike Falcon Spotlight](https://www.crowdstrike.com/) vulnerability export.

This exists for organisations that cannot grant Falcon API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro CrowdStrike Spotlight
connector pulls the same data over the API; this parser accepts the same data as a file.

### File Types

JSON. Export combined Spotlight vulnerability entities from the Falcon API, for example:

```
curl -H "Authorization: Bearer $FALCON_TOKEN" "https://api.crowdstrike.com/spotlight/combined/vulnerabilities/v1?filter=status:'open'&facet=cve&facet=host_info&facet=remediation" > spotlight.json
```

A bare JSON array of vulnerabilities is accepted, as is the API's `resources` envelope.

Note this is Spotlight **vulnerabilities** only. Falcon **Detections** are a different shape and are
imported under their own scan type by the connector; this parser does not claim that scan type.

### Scan type and deduplication

The scan type is **`CrowdStrike:Spotlight - Connectors Import`** — identical to the string the
Spotlight connector reports. That is deliberate: a customer who uploads an export *and* later enables
the connector gets one set of findings that deduplicate, rather than two copies of everything.

Deduplication identity is the Spotlight vulnerability id, carried as `unique_id_from_tool`.

### Severity

Severity comes from the **CVE's** severity, not the vulnerability's, mirroring the connector:
`CRITICAL`→Critical, `HIGH`→High, `MEDIUM`→Medium, `LOW`→Low, and anything unrecognised→Info. The
comparison is case-insensitive.

The CVSS vector and base score are imported, and the connector's severity justification sentence is
reproduced — it records CrowdStrike's own grade, the base score, and the ExPRT rating.

### Neither static nor dynamic

Findings are marked **neither** `static_finding` **nor** `dynamic_finding`, which is what the
connector does. Spotlight reports vulnerable software present on a host from the Falcon agent's
inventory: it does not analyse source, and it does not probe a running service. This parser mirrors
the connector rather than picking one.

### Fields worth noting

- **Component version** — CrowdStrike returns no discrete version field, so the version is whatever
  remains of `product_name_version` once the normalized product name is stripped from the front.
- **CWE** — the first entry of `cve.cwes` that parses as `CWE-<number>`; entries that do not parse are
  skipped, and a list with none parseable leaves the CWE at 0.
- **Host** — the finding records `host_info.hostname`, falling back to `local_ip`.
- **Tags** — the ExPRT rating (`exprt:<rating>`), `cisa-kev` when the CVE is in the CISA Known
  Exploited Vulnerabilities catalog, and the host's own Falcon tags.

### Sample Scan Data

Sample CrowdStrike Spotlight scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/crowdstrike_spotlight).

The samples are constructed from the documented Spotlight combined-vulnerabilities schema, with
generic hostnames, private-range addresses and placeholder CVE identifiers.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- unique_id_from_tool
- title
- severity
- vulnerability_ids
