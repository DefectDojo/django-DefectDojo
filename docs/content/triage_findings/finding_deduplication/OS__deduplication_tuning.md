---
title: "Deduplication Tuning"
description: "Configure deduplication in DefectDojo Open Source: algorithms, hash fields, endpoints, and service"
weight: 5
audience: opensource
aliases:
  - /en/working_with_findings/finding_deduplication/deduplication_tuning_os
  - /en/working_with_findings/finding_deduplication/deduplication_algorithms
---
The Open Source edition of DefectDojo uses settings files and environment variables tune deduplication.

See also: [Open Source Configuration](/get_started/open_source/configuration/) for details on environment variables and `local_settings.py` overrides.

## What you can configure

- **Algorithm per parser**: Choose one of Unique ID From Tool, Hash Code, Unique ID From Tool or Hash Code, or Legacy (OS only).
- **Hash fields per scanner**: Decide which fields contribute to the hash for each parser.
- **Allow null CWE**: Control whether a missing/zero CWE is acceptable when hashing.
- **Endpoint consideration**: Optionally use endpoints for deduplication when they’re not part of the hash.
- **Always-included fields**: Add fields (e.g., `service`) to all hashes regardless of per-scanner settings.

## Key settings (defaults shown)

All defaults are defined in `dojo/settings/settings.dist.py`. Override via environment or `local_settings.py`.

### Algorithm per parser

- Setting: `DEDUPLICATION_ALGORITHM_PER_PARSER`
- Values per parser: one of `unique_id_from_tool`, `hash_code`, `unique_id_from_tool_or_hash_code`, `legacy`.
- Example (env variable JSON string):

```bash
DD_DEDUPLICATION_ALGORITHM_PER_PARSER='{"Trivy Scan": "hash_code", "Veracode Scan": "unique_id_from_tool_or_hash_code"}'
```

### Hash fields per scanner

- Setting: `HASHCODE_FIELDS_PER_SCANNER`
- Example default for Trivy in OS:

```startLine:endLine:dojo/settings/settings.dist.py
1318:1321:dojo/settings/settings.dist.py
    "Trivy Operator Scan": ["title", "severity", "vulnerability_ids", "description"],
    "Trivy Scan": ["title", "severity", "vulnerability_ids", "cwe", "description"],
    "TFSec Scan": ["severity", "vuln_id_from_tool", "file_path", "line"],
    "Snyk Scan": ["vuln_id_from_tool", "file_path", "component_name", "component_version"],
```

- Override example (env variable JSON string):

```bash
DD_HASHCODE_FIELDS_PER_SCANNER='{"ZAP Scan":["title","cwe","severity"],"Trivy Scan":["title","severity","vulnerability_ids","description"]}'
```

### Allow null CWE per scanner

- Setting: `HASHCODE_ALLOWS_NULL_CWE`
- Controls per parser whether a null/zero CWE is acceptable in hashing. If False and the finding has `cwe = 0`, the hash falls back to the legacy computation for that finding.

### Always-included fields in hash

- Setting: `HASH_CODE_FIELDS_ALWAYS`
- Default: `["service"]`
- Impact: Appended to the hash for every scanner. Removing `service` here stops it from affecting hashes across the board.

```startLine:endLine:dojo/settings/settings.dist.py
1464:1466:dojo/settings/settings.dist.py
# Adding fields to the hash_code calculation regardless of the previous settings
HASH_CODE_FIELDS_ALWAYS = ["service"]
```

### Optional endpoint-based dedupe

- Setting: `DEDUPE_ALGO_ENDPOINT_FIELDS`
- Default: `["host", "path"]`
- Purpose: If endpoints are not part of the hash fields, you can still require a minimal endpoint match to deduplicate. If the list is empty `[]`, endpoints are ignored on the dedupe path.

```startLine:endLine:dojo/settings/settings.dist.py
1491:1499:dojo/settings/settings.dist.py
# Allows to deduplicate with endpoints if endpoints is not included in the hashcode.
# Possible values are: scheme, host, port, path, query, fragment, userinfo, and user.
# If a finding has more than one endpoint, only one endpoint pair must match to mark the finding as duplicate.
DEDUPE_ALGO_ENDPOINT_FIELDS = ["host", "path"]
```

## Endpoints: how to tune

Endpoints can affect deduplication via two mechanisms:

1) Include `endpoints` in `HASHCODE_FIELDS_PER_SCANNER` for a parser. Then endpoints are part of the hash and must match exactly according to the parser’s hashing rules.
2) If endpoints are not in the hash fields, use `DEDUPLE_ALGO_ENDPOINT_FIELDS` to specify attributes to compare. Examples:
   - `[]`: endpoints are ignored for dedupe.
   - `["host"]`: findings dedupe if any endpoint pair matches by host.
   - `["host", "port"]`: findings dedupe if any endpoint pair matches by host AND port.

Notes:

- For Legacy algorithm, static vs dynamic findings have different endpoint matching rules (see the algorithms page). The `DEDUPLE_ALGO_ENDPOINT_FIELDS` setting applies to the hash-code path, not the Legacy algorithm’s intrinsic logic.
- For `unique_id_from_tool` (ID-based) matching, endpoints are ignored for the dedupe decision.

## Service field: dedupe and reimport

- With default `HASH_CODE_FIELDS_ALWAYS = ["service"]`, the `service` field is appended to the hash. Two otherwise equal findings with different `service` values will not dedupe on hash-based paths.
- During import via UI/API, the `Service` input can override the parser-provided service. Changing it changes the hash and can alter dedupe behavior and reimport matching.
- If you want dedupe independent of service, remove `service` from `HASH_CODE_FIELDS_ALWAYS` or leave the `Service` field empty during import.

## After changing deduplication settings

- Changes to dedupe configuration (e.g., `HASHCODE_FIELDS_PER_SCANNER`, `HASH_CODE_FIELDS_ALWAYS`, `DEDUPLICATION_ALGORITHM_PER_PARSER`) are not applied retroactively automatically. To re-evaluate existing findings you must run the management command below.

Run inside the uwsgi container. Example (hash codes only, no dedupe):

```bash
docker compose exec uwsgi /bin/bash -c "python manage.py dedupe --hash_code_only"
```

Help/usage:
```
options:
  --parser PARSER       List of parsers for which hash_code needs recomputing
                        (defaults to all parsers)
  --hash_code_only      Only compute hash codes
  --dedupe_only         Only run deduplication
  --dedupe_sync         Run dedupe in the foreground, default false
```

If you submit dedupe to Celery (without `--dedupe_sync`), allow time for tasks to complete before evaluating results.

## Where to configure

- Prefer environment variables in deployments. For local development or advanced overrides, use `local_settings.py`.
- See `configuration.md` for details on how to set environment variables and configure local overrides.

### Troubleshooting

To help troubleshooting deduplication use the following tools:

- Observe log out in the `dojo.specific-loggers.deduplication` category. This is a class independant logger that outputs details about the deduplication process and settings when processing findings.
- Observe the `unique_id_from_tool` and `hash_code` values by hovering over the `ID` field or `Status` column:

![Unique ID from Tool and Hash Code on the View Finding page](images/hash_code_id_field.png)

![Unique ID from Tool and Hash Code on the Finding List Status Column](images/hash_code_status_column.png)
