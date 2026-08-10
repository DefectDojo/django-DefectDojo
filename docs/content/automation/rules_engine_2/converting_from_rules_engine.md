---
title: "Converting from Rules Engine"
description: "Move existing Rules Engine rules across to Rules Engine 2.0 graphs"
weight: 6
audience: pro
aliases:
  - /automation/rules_engine_v2/converting_from_rules_engine/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

Both engines run side by side. Turning on Rules Engine 2.0 changes nothing about your existing [Rules Engine](/automation/rules_engine/about/) rules, and there is no deadline by which you must move them.

When you do want to move them, there is a converter. It translates a Rules Engine rule (a filter plus an ordered list of actions) into an equivalent Rules Engine 2.0 graph.

## What the converter guarantees

**A rule either converts cleanly or it does not convert at all.** Every conversion reports two kinds of result:

* **Problems** mean the rule was not written. Nothing partial is saved.
* **Warnings** mean the rule converted, but something about it moved and you should look at it.

Nothing is silently approximated. The whole value of the converter is that you can trust a rule that converted without remark, and hand-check one that did not.

**Converted rules are always created disabled.** Both engines are running, and two rules doing the same thing to the same Findings is the one outcome a converter must never produce on its own. Review each converted rule and enable it deliberately.

**A rule converts once.** Each converted rule remembers the rule it came from, so running the converter twice skips what it already did rather than creating duplicates. Use the overwrite option to deliberately replace a previously converted graph.

## Running the converter

### From the UI

The rule list offers a conversion action, which reports per rule what converted, what was skipped, and what failed.

### From the command line

```bash
python manage.py convert_rules_to_v2
```

| Option | Effect |
|--------|--------|
| `--dry-run` | Print the graph each rule would produce and write nothing. |
| `--rule-ids 1,2,3` | Convert only these rules. Converts every rule when omitted. |
| `--overwrite` | Replace the graph of an already-converted rule and bump its version, instead of skipping it. |
| `--activate-schedules` | Also copy each schedule onto its converted rule. Off by default. |
| `--drop-invalid-filters` | Drop scope filters the filter set no longer recognises and warn, instead of failing the rule. |
| `--json` | Print the report as JSON instead of text. |

The command exits non-zero only when a rule fails to convert. Skips are reported but are not failures.

Start with `--dry-run` on the full set to see what you are in for, then convert for real.

## What the conversion produces

| Rules Engine concept | Becomes |
|----------------------|---------|
| The rule's filter | The **Scope** on the trigger node. |
| A rule with a schedule | An **On a Schedule** trigger. |
| A rule with no schedule | A **Manual Run** trigger. |
| Each action, in order | One node, chained in the same order. |
| An action guarded by a condition | An **If / Filter** node in front of that node. |

The filter vocabulary is shared between both engines, so a scope converts without translation. That is deliberate: it is the same filter set, with one implementation.

Converted graphs are validated the same way a hand-built graph is, including per-node configuration and the allowed values of every dropdown. A rule holding a severity or risk value that the product has since moved on from is caught at conversion rather than at run time.

## What does not carry over

Four things to plan for. The converter reports these as notes on every run.

* **Run history stays where it is.** Existing run history, and its affected and skipped records, remain in the Rules Engine UI. They are not copied.
* **Schedules are not activated by default.** A schedule-triggered rule converts, but its schedule is not copied unless you pass `--activate-schedules`. This keeps sole ownership of live schedules with the original engine while both are running, so a converted rule cannot start firing behind your back. When you do copy a schedule, the copy is given a distinct name so it does not collide with the original.
* **The concurrency model is different.** Rules Engine has one instance-wide run lock. Rules Engine 2.0 serialises per rule, so distinct rules run concurrently. A set of rules that used to take turns will now overlap.
* **One action has no equivalent.** A "set false positive to false" action cannot be expressed as a Rules Engine 2.0 node and must be converted by hand.

A rule whose owner is unset converts, with a warning. Remember that a rule with no owner sees no Findings, so assign one before enabling it.

## A suggested order

1. Turn on Rules Engine 2.0 and leave your existing rules running.
2. Run the converter with `--dry-run` and read the report.
3. Convert. Everything lands disabled.
4. Open each converted rule, check the graph, and leave the mode on **Simulate**.
5. Enable the converted rule, and let it run alongside the original for a while. Simulate means it changes Findings but sends nothing, so compare its runs against what the original did.
6. When you are satisfied, disable the original rule and switch the converted one to **Live**.
7. Copy the schedule across last, once nothing is running the old rule any more.

Step 5 is the one worth not skipping. Both engines editing the same Findings is fine to observe, but you want to be the one who decides when the sends start.
