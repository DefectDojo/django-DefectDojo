---
title: "Promptfoo (LLM eval & red-teaming)"
toc_hide: true
---
Input Type:
-
This parser imports the JSON results file produced by [promptfoo](https://promptfoo.dev), an LLM evaluation and red-teaming tool.

Generate the file with `promptfoo eval -o results.json` or, for an adversarial scan, `promptfoo redteam run -o results.json`, and upload that JSON file.

Tested against the promptfoo results schema (`results.version == 3`).

Things to note about the Promptfoo parser:
-

- **Inverted pass/fail semantics.** promptfoo reports `success: true` when every assertion passes; for a red-team probe that means the target model *defended* the attack, so it is **not** a finding. Only results with `success: false` (a failed assertion / a successful attack) become Findings.
- **Aggregation:** failures for the same red-team plugin (`pluginId`) against the same target (provider) are aggregated into a single Finding, with `nb_occurences` reflecting the number of failed attempts and the most severe rung retained.
- **Severity** comes from the red-team `metadata.severity` (`critical`/`high`/`medium`/`low`). A plain `promptfoo eval` failure carries no severity metadata and defaults to **Medium**.
- **CWE** is mapped from the plugin / harm category as a starter mapping (refined over time):
   - SQL-injection plugin -> **CWE-89**; shell/command-injection plugin -> **CWE-78**
   - prompt-injection / prompt-extraction plugins -> **CWE-1427** (Improper Neutralization of Input Used for LLM Prompting)
   - PII / privacy plugins -> **CWE-200** (Exposure of Sensitive Information to an Unauthorized Actor)
   - everything else -> **CWE-1426** (Improper Validation of Generative AI Output)
- **Errored results** (`failureReason == 2`, a provider/eval error rather than an assertion failure) are skipped: they indicate the test could not run, not a vulnerability.

### Sample Scan Data
Sample scan data for testing purposes can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/promptfoo).

### Deduplication
The "Promptfoo Scan" scan type uses the `hash_code` [deduplication algorithm](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/) with the following fields:

- title (the harm category and plugin id, e.g. *Hate (harmful:hate)*)
- component_name (the scanned provider / target model)

`description` and `severity` are intentionally **excluded** from the hashcode. `description` holds the specific attack input and model output, which promptfoo varies per run. `severity` is an aggregate value that can shift as the set of failed attempts changes between scans. Including either would stop the same weakness from deduplicating across repeated scans of the same target.
