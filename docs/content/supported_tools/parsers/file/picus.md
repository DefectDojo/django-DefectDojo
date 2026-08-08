---
title: "PICUS Scan"
toc_hide: true
---

The [Picus Security](https://www.picussecurity.com/) parser for DefectDojo supports imports from CSV format. Picus is a Breach and Attack Simulation (BAS) platform that runs simulated attacks against an environment and reports whether existing security controls prevented, logged, and alerted on each simulated action. This document details how Picus result CSV exports are mapped into DefectDojo Findings, which fields are parsed, and the BAS-specific transformation notes.

## Supported File Types

The Picus parser accepts CSV file format. Picus exports a separate CSV per attack vector (for example Email, Endpoint, Network, and Web), but all share an identical column schema, so the same parser handles every export.

To import Picus results into DefectDojo:

1. Log into your Picus console
2. Run or open the simulation whose results you want to import
3. Export the results as CSV (one file per attack vector)
4. Save each file with a `.csv` extension
5. Upload each CSV to DefectDojo using the "PICUS Scan" scan type

DefectDojo imports a single scan file at a time and does not unpack archives. If the export is delivered as a `.rar` or `.zip`, extract it first and import each CSV individually. Each file becomes its own import, which keeps the attack vectors (Email, Endpoint, Network, Web) grouped separately.

## Default Deduplication Hashcode Fields

Picus findings deduplicate using the hashcode algorithm on a single stable [hashcode field](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/), the tool-native action identifier:

- vuln_id_from_tool (populated from the Picus `actionId`)

### Sample Scan Data

Sample Picus scans can be found in the [sample scan data folder](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/picus).

## Link To Tool

- [Picus Security](https://www.picussecurity.com/)
- [Picus Documentation](https://docs.picussecurity.com/)

## CSV Format

### Total Fields in CSV

- Total data fields: 63
- Total data fields parsed into dedicated Finding fields, the structured description, or the mitigation: 26
- Remaining fields (detection-integration, protocol-level, file-hash, and other signature/metadata columns) are not currently mapped

### CSV Format Field Mapping Details

<details>
<summary>Click to expand Field Mapping Table</summary>

| Source Field           | DefectDojo Field          | Notes                                                                                  |
| ---------------------- | ------------------------- | -------------------------------------------------------------------------------------- |
| threatName + actionName | title                    | Combined as "threatName - actionName"; truncated to 500 characters with "..." if longer |
| threatSeverity         | severity                  | Mapped to DefectDojo severity levels; defaults to Info if unrecognized                  |
| threatPreventionResult | active                    | "Not Blocked" sets active=True (control gap); any other value sets active=False         |
| threatPreventionResult | mitigation                | Recommendation sentence plus the "Prevention" line of the control-posture block         |
| threatDetectionLogResult | mitigation              | "Logging" line of the mitigation control-posture block                                  |
| threatDetectionAlertResult | mitigation            | "Alerting" line of the mitigation control-posture block                                 |
| genericMitigationsTabLink | mitigation             | Picus mitigation-guidance link; included in the mitigation references when present       |
| detectionContentTabLink | mitigation               | Detection-content link; included in the mitigation references when present              |
| actionPayloadOutputTabLink | mitigation            | Payload-output link; included in the mitigation references when present                 |
| actionLogsTabLink      | mitigation                | Action-logs link; included in the mitigation references when present                    |
| signatureName + signatureId | mitigation           | Detection signature reference; included in the mitigation references when present       |
| actionId               | vuln_id_from_tool         | Native Picus action identifier; drives hashcode deduplication across re-imports          |
| cve                    | unsaved_vulnerability_ids | Comma-separated CVEs split into a list; omitted when empty                              |
| cwe                    | cwe                       | Parsed to integer when the field contains digits; omitted otherwise                     |
| actionMitreTactic      | unsaved_tags              | Added as a tag when present                                                             |
| actionMitreTechnique   | unsaved_tags              | Added as a tag when present                                                             |
| actionMitreSubtechnique | unsaved_tags             | Added as a tag when present                                                             |
| attackCategory         | unsaved_tags              | Added as a tag when present                                                             |
| affectedProducts       | component_name            | The affected product reported by the simulation                                         |
| threatName             | description               | Included in the structured description table                                            |
| actionName             | description               | Included in the structured description table                                            |
| actionDescription      | description               | Included in the structured description table                                            |
| attackModules          | description               | Included in the structured description table                                            |
| threatDetectionLogResult | description             | Included in the structured description table                                            |
| threatDetectionAlertResult | description           | Included in the structured description table                                            |
| affectedOs             | description               | Included in the structured description table                                            |
| affectedPlatforms      | description               | Included in the structured description table                                            |
| actionPayload          | description               | Included in the structured description table                                            |

</details>

### Additional Finding Field Settings (CSV Format)

<details>
<summary>Click to expand Additional Settings Table</summary>

| Finding Field   | Default Value                 | Notes                                                                       |
| --------------- | ----------------------------- | --------------------------------------------------------------------------- |
| static_finding  | False                         | Picus results reflect runtime simulation behavior, not static analysis      |
| dynamic_finding | True                          | Picus results reflect runtime simulation behavior                           |
| active          | True when "Not Blocked"       | A simulated attack that was not blocked is an open control gap              |

</details>

## Special Processing Notes

### Breach and Attack Simulation Semantics

Picus is a BAS tool, so each CSV row is a simulated attack *action* rather than a discovered vulnerability. The value to DefectDojo is whether a security control stopped the simulated attack. The parser imports every action as a Finding and uses `threatPreventionResult` to decide the finding's active state:

- `Not Blocked` → active Finding (the control failed to stop the attack — an open gap)
- `Blocked` (or any other value) → inactive Finding (the control mitigated the attack)

This preserves the full simulation history while surfacing unmitigated gaps as the actionable findings.

### Severity Mapping

Severity is taken from the `threatSeverity` column (the inherent risk of the threat scenario), not the per-action `severity` column:

- `Critical` → Critical
- `High` → High
- `Medium` → Medium
- `Low` → Low
- `Info` / `Informational` → Info

Any unrecognized value defaults to Info.

### Title Format

Finding titles combine the threat and action names as "threatName - actionName". When only a threat name is present, it is used alone. Titles longer than 500 characters are truncated to 497 characters with a "..." suffix.

### Description Construction

The parser builds a markdown table containing the threat, action, attack category, MITRE references, detection/prevention results, affected asset details, payload, and the Picus simulation/action identifiers. Empty source fields are omitted, and pipe characters in values are escaped so the table renders correctly.

### Mitigation Construction

The mitigation field is assembled to give an analyst what they need to remediate the gap, not just a status sentence. It contains up to three parts, and any part with no underlying data is omitted:

1. **Recommendation sentence** — derived from `threatPreventionResult` (a prompt to tune controls when the attack was "Not Blocked", or a confirmation when it was "Blocked").
2. **Control posture** — the prevent → log → alert results (`threatPreventionResult`, `threatDetectionLogResult`, `threatDetectionAlertResult`) so the analyst can see which control layer failed and where to focus first.
3. **Mitigation & triage references** — the Picus links and identifiers that help build a fix: mitigation guidance (`genericMitigationsTabLink`), detection content (`detectionContentTabLink`), payload output (`actionPayloadOutputTabLink`), action logs (`actionLogsTabLink`), and the detection signature (`signatureName` / `signatureId`). Each reference is included only when present in the export.

When none of these parts has data, the mitigation field is left unset rather than written as an empty string.

### Deduplication

Deduplication uses the hashcode algorithm keyed solely on `vuln_id_from_tool`, which the parser populates from the native Picus `actionId`. The `actionId` is stable across simulation runs (the same attack action keeps the same identifier), while `simulationRunId` changes on every run. Keying on `actionId` alone — and deliberately excluding `simulationRunId` — means that when a later run's CSV is re-imported into the same test, each action matches its prior finding. This lets DefectDojo update the status of existing findings (for example, closing an action that was previously "Not Blocked" once a control begins blocking it) rather than creating duplicates. Picus simulations span an asset class such as Network or Email, so deduplication is expected to operate within a single asset/engagement rather than across asset types.

### Unmapped Fields

Detection-integration, protocol-level prevention/detection, file-hash, and remaining signature/metadata columns are retained in the source CSV but are not currently mapped to Finding fields. The most operationally relevant columns are surfaced either as dedicated Finding fields, within the structured description table, or in the mitigation references.
