---
title: "Deduplication Algorithms"
description: "How DefectDojo identifies duplicates: Unique ID, Hash Code, Unique ID or Hash Code, Legacy"
weight: 3
---

## Overview

DefectDojo supports four deduplication algorithms that can be selected per parser (test type):

- **Unique ID From Tool**: Uses the scanner-provided unique identifier.
- **Hash Code**: Uses a configured set of fields to compute a hash.
- **Unique ID From Tool or Hash Code**: Prefer the tool’s unique ID; fall back to hash when no matching unique ID is found.
- **Legacy**: Historical algorithm with multiple conditions; only available in the Open Source version.

Algorithm selection per parser is controlled by `DEDUPLICATION_ALGORITHM_PER_PARSER` (see the [Open-Source tuning page](/en/working_with_findings/finding_deduplication/deduplication_tuning_os/) for configuration details).

## How endpoints are assessed per algorithm

Endpoints can influence deduplication in different ways depending on the algorithm and configuration.

### Unique ID From Tool

- Deduplication uses `unique_id_from_tool` (or `vuln_id_from_tool`).
- **Endpoints are ignored** for duplicate matching.
- A finding’s hash may still be calculated for other features, but it does not affect deduplication under this algorithm.

### Hash Code

- Deduplication uses a hash computed from fields specified by `HASHCODE_FIELDS_PER_SCANNER` for the given parser.
- The hash also includes fields from `HASH_CODE_FIELDS_ALWAYS` (see Service field section below).
- Endpoints can affect deduplication in two ways:
  - If the scanner’s hash fields include `endpoints`, they are part of the hash and must match accordingly.
- If the scanner’s hash fields do not include `endpoints`, optional endpoint-based matching can be enabled via `DEDUPE_ALGO_ENDPOINT_FIELDS` (OS setting). When configured:
    - Set it to an empty list `[]` to ignore endpoints entirely.
    - Set it to a list of endpoint attributes (e.g. `["host", "port"]`). If at least one endpoint pair between the two findings matches on all listed attributes, deduplication can occur.

### Unique ID From Tool or Hash Code
A finding is a duplicate with another if they have the same unique_id_from_tool OR the same hash_code.

The endpoints also have to match for the findings to be considered duplicates, see the Hash Code algorithm above.

### Legacy (OS only)

- Deduplication considers multiple attributes including endpoints.
- Behavior differs for static vs dynamic findings:
  - **Static findings**: The new finding must contain all endpoints of the original. Extra endpoints on the new finding are allowed.
  - **Dynamic findings**: Endpoints must strictly match (commonly by host and port); differing endpoints prevent deduplication.
- If there are no endpoints and both `file_path` and `line` are empty, deduplication typically does not occur.

## Background processing

- Dedupe is triggered on import/reimport and during certain updates run via Celery in the background.

## Service field and its impact

- By default, `HASH_CODE_FIELDS_ALWAYS = ["service"]`, meaning the `service` associated with a finding is appended to the hash for all scanners.
- Practical implications:
  - Two otherwise identical findings with different `service` values will produce different hashes and will not deduplicate under Hash-based paths.
  - During import/reimport, the `Service` field entered in the UI can override the parser-provided service. Changing it can change the hash and therefore affect deduplication outcomes.
  - If you want service to have no impact on deduplication, configure `HASH_CODE_FIELDS_ALWAYS` accordingly (see the OS tuning page). Removing `service` from the always-included list will stop it from affecting hashes.

See also: the [Open Source tuning guide](/en/working_with_findings/finding_deduplication/deduplication_tuning_os/) for configuration details and examples.
