---
title: "PyRIT"
toc_hide: true
---
Import PyRIT attack results in JSON format. PyRIT — the Python Risk Identification Tool for
generative AI, from Microsoft — runs automated red-teaming attacks against a generative AI target
and records the outcome of each attack.

PyRIT keeps its results in a memory store rather than writing a report file directly, so export
them to JSON from that store. A JSON array of attack results is accepted, as is an object holding
them under `results` or `attack_results`.

### What one Finding represents
**One attack result becomes one Finding**, titled with the attack strategy and the objective it was
pursuing. Each records the outcome, how many turns it took, the conversation id it belongs to, and
the scorer's verdict on the final response, so the evidence trail back into PyRIT's memory store
stays intact.

Attacks whose outcome is `failure` are **not imported**. A failure means PyRIT tried and the target
refused — the guardrails did their job — which is a passing test, in the same way a satisfied policy
check is not a finding.

### Severity Mapping
PyRIT has no severity field. What it does have is an outcome per attack, and the outcome is a real
verdict on the target rather than a guess, so severity is derived from it. The four outcomes are the
ones in
[attack_result.py](https://github.com/microsoft/PyRIT/blob/main/pyrit/models/results/attack_result.py):

| PyRIT outcome | DefectDojo severity | Reasoning |
| --- | --- | --- |
| `success` | High | The attack achieved its objective: the target produced what it should have refused. This is a demonstrated guardrail failure. |
| `undetermined` | Low | PyRIT could not tell whether the objective was met, so a human needs to read the conversation. |
| `error` | Info | An infrastructure error — a rate limit, a timeout — not a refusal. The attack never completed, so nothing about the target was established. |
| `failure` | not imported | The target refused. |

Note that severity reflects **whether the guardrails held**, not how alarming the objective sounds.
An attack objective is free text written by whoever ran the campaign; grading on its wording would
be grading the tester's prose. The harm categories PyRIT was targeting are attached to the Finding
as tags, along with the outcome, so a campaign can be filtered by harm without severity pretending
to encode it.

Where a scorer ran, its type, value and rationale are recorded in the description. A `float_scale`
score is deliberately not folded into severity: PyRIT scorers are configured per campaign and their
scales are not comparable between runs.

### Sample Scan Data
Sample PyRIT scans can be found [here](https://github.com/DefectDojo/django-DefectDojo/tree/master/unittests/scans/pyrit).

### Default Deduplication Hashcode Fields
By default, DefectDojo identifies duplicate Findings using these [hashcode fields](https://docs.defectdojo.com/en/working_with_findings/finding_deduplication/about_deduplication/):

- title
- vuln_id_from_tool
