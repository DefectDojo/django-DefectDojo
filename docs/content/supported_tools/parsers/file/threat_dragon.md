---
title: "OWASP Threat Dragon"
toc_hide: true
---
Import OWASP Threat Dragon threat models in JSON format. Threat Dragon is a threat modelling
tool; its models hold diagrams whose elements carry the threats identified against them.

Export the model from Threat Dragon and import the resulting `.json` file directly.

### Severity Mapping
Threat Dragon records a severity per threat, which DefectDojo maps directly:

| Threat Dragon severity | DefectDojo severity |
| --- | --- |
| Critical | Critical |
| High | High |
| Medium | Medium |
| Low | Low |
| TBD | Info |

Threats the modeller has marked as **Mitigated** are imported as mitigated, inactive Findings
rather than being dropped, so the decisions recorded in the model survive the import. Open
threats import as active.

Each Finding records the STRIDE category, the diagram element the threat applies to, and the
diagram and model titles.

Both Threat Dragon schema versions are handled: v1 models nest diagram cells under
`diagramJson` and label them through their rendering attributes, while v2 models carry cells
and names directly.

### Sample Scan Data
Sample Threat Dragon models can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/threat_dragon).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- component_name
- severity
