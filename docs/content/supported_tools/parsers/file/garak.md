---
title: "Garak (LLM vulnerability scanner)"
toc_hide: true
---
Input Type:
-
This parser imports the JSON Lines **hit log** produced by [garak](https://github.com/NVIDIA/garak), NVIDIA's LLM vulnerability scanner.

A garak run writes `garak.<run_id>.hitlog.jsonl` alongside its `report.jsonl`. Every line in the hit log is, by construction, a detector hit, so each record is mapped to a DefectDojo Finding. Upload the `*.hitlog.jsonl` file (not `report.jsonl`).

Tested against the garak 0.15.x hit-log schema (`garak/evaluators/base.py`).

Things to note about the Garak parser:
-
- **Aggregation:** hits for the same probe, target (generator), and detector are aggregated into a single Finding, with `nb_occurences` reflecting the number of hits and the most severe rung retained.
- **Severity** is derived from the detector `score` (0.0-1.0) and adjusted by probe family. Active-attack / code-execution / jailbreak families (e.g. `promptinject`, `dan`, `malwaregen`, `xss`) are nudged up one rung; content/quality families (e.g. `continuation`, `misleading`, `toxicity`) are nudged down one rung. Note that many garak detectors are string/word-list matchers that emit a binary score of `1.0`, so most real hits land in the upper severity bands.
- **CWE** is mapped from the probe family as a starter mapping (refined over time):
   - prompt-injection families (`promptinject`, `dan`, `latentinjection`, `goodside`) -> **CWE-1427** (Improper Neutralization of Input Used for LLM Prompting)
   - `xss` -> **CWE-79**
   - `leakreplay`, `divergence` -> **CWE-200**
   - all other families -> **CWE-1426** (Improper Validation of Generative AI Output)
- A hit log with no detector hits yields no findings. Lines that are not hit records (anything without a `probe` field, such as run/config metadata) are ignored.

JSON Lines Format:
-
The parser accepts a `.jsonl` hit log. Each line is one hit record with fields including `goal`, `prompt`, `output`, `triggers`, `score`, `probe`, `detector`, and `generator`. The `prompt` and `output` values are serialized garak conversation/message objects (nested dicts), from which the parser extracts the displayed text.

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/garak).

### Deduplication
The "Garak Scan" scan type uses the `hash_code` [deduplication algorithm](/en/working_with_findings/finding_deduplication/about_deduplication/) with the following fields:

- title (the garak probe and its goal)
- component_name (the scanned model / generator)

`description` and `severity` are intentionally **excluded** from the hashcode. `description` holds the specific prompt and model output for the hit, which garak samples non-deterministically on each run. `severity` is an aggregate value — the most severe rung seen across a probe's occurrences — so it shifts as the occurrence set changes between scans. Including either would stop the same weakness from deduplicating across repeated scans of the same model.
