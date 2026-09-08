---
title: "Vanta"
toc_hide: true
---

Import a [Vanta](https://www.vanta.com/) compliance export.

This exists for organisations that cannot grant Vanta API credentials — air-gapped networks,
procurement restrictions, a pending security review. The DefectDojo Pro Vanta connector pulls the same
data over the API; this parser accepts the same data as a file.

### File Types

JSON — the tests response, with rows under `results.data`. A bare array of tests is accepted too.

**Include each test's failing entities.** A Vanta finding is a *(test, failing entity)* pair: the test
is the control ("MFA is enabled for all users") and the entity is the resource failing it. A test with
no failing entity is the control working, and produces nothing. Because those rows carry no test id of
their own, supply them as:

- a top-level `entities` object keyed by test id — each value either the paged
  `{"results": {"data": [...]}}` response or a bare list, or
- an `entities` array (or paged response) nested on each test.

Only entities Vanta reports as `FAILING` become findings. The connector asks Vanta for the failing ones
specifically, so an export carrying every entity is filtered here instead. An entity with **no** status
is taken at its word and treated as failing, since the connector never sees any other kind.

### Severity is always Medium

Vanta has no severity scale — a compliance test passes or fails. The connector grades every failing
entity **Medium** rather than inventing a ladder, and this parser does the same. Info would read as
non-actionable, and a failing control is actionable by definition.

That makes `component_name` load-bearing: it is the failing entity, and it is what keeps two resources
failing the same control from merging, since they share a title and a severity.

### One finding per failing resource

The identity is `vanta-<test id>-<entity id>`. Both findings for one control carry the same
`vuln_id_from_tool` (the test id), so they group as the same control while remaining separate findings.

### Fields worth noting

- **Date** is when the *entity* started failing, falling back to when the test last flipped. One
  control can have been failing for a year while a resource added last week has only just started
  failing it.
- **Mitigation** is Vanta's own remediation description.
- **Tags** carry `compliance`, the test's category, its integrations and the entity's response type.
- **Every finding is static and active** — Vanta evaluates configuration and records, not a running
  request, and a failing entity is failing now.

### Sample Scan Data

Sample Vanta scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/vanta).

The samples are constructed from Vanta's documented tests and entities responses and cover one control
failing on two resources, a passing entity that must be skipped, a test with no failing entities, a
test with no name, an unparseable entity date, a test with no integrations, and both the paged and
bare-list entity shapes. Resource names and email addresses are generic.

### Default Deduplication Hashcode Fields

By default, DefectDojo identifies duplicate findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- severity
- component_name
