---
title: "Runs"
description: "How a rule executes, what a run records, and how cascading is bounded"
weight: 4
audience: pro
aliases:
  - /automation/rules_engine_v2/runs/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine 2.0 is a DefectDojo Pro-only feature.</span>

A **run** is one execution of one rule. Every run is recorded, whether it succeeded or failed, and every node inside it leaves a trace. **Rules Engine 2.0 > Runs** lists them.

## What a run records

| Field | Meaning |
|-------|---------|
| **Rule** | The rule that executed. |
| **Trigger** | The event that started it, for example `finding.created`, `schedule` or `manual`. |
| **Triggered by** | The person who set it off, when a person did: whoever pressed Run, or whoever saved the Finding that triggered it. Empty for a schedule, and for a change nobody was present for such as an import or an API call with no user. This is distinct from the rule's owner, which is who the run executed **as**. |
| **Status** | `Running`, `Success` or `Error`. |
| **Started** and **Finished** | When it ran. Finished is empty only while it is still running. |
| **Error** | The error that ended it, if it failed. |
| **Stats** | Per-node totals, cascaded events, and deferred work. |
| **Depth** | How many cascade hops away from the originating event this run is. |
| **Source run** | The run whose emitted event triggered this one, for a cascaded run. |

### The node trace

Inside a run, every node records its own row:

| Field | Meaning |
|-------|---------|
| **Order** | Where the node sat in the execution order. |
| **Node** | Its id, its type, and its label if you gave it one. |
| **Status** | Whether the node completed or raised. |
| **Items in** | How many items entered. |
| **Items out** | How many left, broken down per output handle, so an If / Filter node shows its true and false counts separately. |
| **Summary** | Whatever counters the node reported, for example how many Findings it changed. |
| **Error** | The error it raised, if it failed. |

The trace is what you read when a rule did not do what you expected. An If / Filter node reporting 400 items in and 0 down the true branch tells you the conditions are wrong, without you having to guess.

## Execution model

Nodes execute in topological order: a node runs once everything feeding into it has run. A node with several incoming edges receives all of their outputs concatenated. A node with nothing feeding into it still runs, with an empty input list.

### A failed run changes nothing

A run is atomic. If any node raises, every Finding change the run made is rolled back.

The trace is not rolled back with it. The node rows and the `Error` status are written afterwards, so a failed run tells you exactly which node broke while leaving no half-applied edits behind. This is the single most important guarantee to keep in mind when reading the Runs page: an errored run is a run that did nothing.

Egress follows the same rule. Deliveries are recorded inside the run's transaction and only dispatched after it commits, so a run that rolls back sends nothing.

### One run per rule at a time

A rule can only have one run in progress. A second trigger for the same rule while it is still running does not race with it. It waits and retries.

Different rules run fully concurrently, so a slow rule never holds up its siblings.

If a run is somehow abandoned, for example because the worker executing it was killed, its lock is released after a stall window (30 minutes by default) so the rule is not wedged forever. A run approaching that window stops itself first, unwinding cleanly, so a merely slow run can never end up executing alongside its own replacement.

## Cascading

A rule that changes a Finding produces exactly the kind of event another rule can trigger on. Rules Engine 2.0 allows that, so `A -> B -> C` chains work, and bounds it in two independent ways:

* **Depth.** An event may travel at most **3** cascade hops from the change that originated it.
* **Chain membership.** Every event carries the list of rules already traversed in its chain, and a rule never runs twice in the same chain. So a rule cannot re-trigger itself, and two rules cannot ping-pong.

A run's **Depth** and **Source run** fields let you follow a chain back to the change that started it. **Triggered by** is carried down the whole chain, so a cascade one person set off stays attributable to them at every hop.

Changes made *by* a running rule are attributed to that rule's own cascade rather than looking like fresh user activity, so a rule delegating work internally does not inflate the chain.

## Scale and limits

**A run is not capped.** A rule processes everything its scope matches, however large that is. A rule that silently stopped at the first N Findings would be a rule you could not trust.

Instead, a run is processed in **chunks**, 1,000 Findings at a time by default. Only the chunk is held in memory, so a sweep over a very large scope is bounded in memory rather than in coverage. The one exception is **Preview**, which does cap, and says so in its trace when it truncates.

Two other numbers shape how work is divided:

* **Findings per event**, 500 by default. A bulk change is split across several events, each becoming its own run. The practical effect for a large import is a manageable number of runs rather than one run per Finding.
* **Per-Finding send ceiling**, 1,000 by default. An egress node set to send one message per Finding stops at this many in a single run and records a visible skip saying how many it did not send about. This bounds delivery rows and queued tasks, which a chunked run no longer bounds on its own.

All three are deployment settings, documented in [Configuration](../configuration/).

### How long a run may take

A run stamps a **heartbeat** after each chunk. Stall detection reads that heartbeat rather than the start time, so a long sweep that is still making progress is never mistaken for a crashed worker.

Two windows apply, both configurable:

* A run that goes 30 minutes without a heartbeat is treated as abandoned, errored, and its lock released.
* A run is killed outright after six hours, as a guard against one that will never finish.

## Retention

Runs are kept for **180 days** by default, along with their per-node rows and their Finding provenance. Deliveries are kept for 180 days separately.

The product tells you this rather than leaving it implicit: a run's detail shows the retention window and the date that run will be deleted. A run still holding deliveries is kept until those are pruned.

Both windows are configurable, and either can be set to keep records indefinitely. See [Configuration](../configuration/#retention).

## Running a rule by hand

A rule whose trigger is **Manual Run** is executed with the **Run** action on the rule list. Rules with other triggers run when their trigger fires.

**Preview**, in the editor, is the other way to execute a graph. It runs the real engine and then rolls everything back, records no run, and forces egress to simulate. Use preview while building, and runs to see what actually happened.

## Provenance on a Finding

Runs answer "what did this rule do?". Provenance answers the opposite question: "why did this Finding change?".

Every change a rule makes is recorded against the Finding with the rule, the run and the node responsible, and appears as a timeline on the Finding itself. The recorded actions are:

| Action | Meaning |
|--------|---------|
| `created`, `updated`, `closed`, `reopened` | The Finding's lifecycle changed. |
| `duplicate`, `status_change` | Its duplicate or status flags changed. |
| `notified` | A notification went out about it. |
| `delivered` | An outbound delivery covered it. |

Field edits record what changed, including the before and after value of each field. Very long values are truncated in the record, so the timeline stays a record of the change rather than a second copy of the Finding.

Notifications and deliveries are recorded here too. That is deliberate: a rule that sent a message but changed no field would otherwise leave no trace on the Finding at all.

Provenance survives the rule. Deleting a rule or a run keeps the timeline entries and simply unlinks them, so history does not disappear when someone tidies up.

## Deleting rules with history

A rule that has produced deliveries cannot be deleted out from under them. Delete the deliveries first, or keep the rule and disable it. This is intentional: deliveries hold the record of what was actually sent to external systems, and a cascade delete would take in-flight sends with it.

## Asset runs

A run of an Asset rule reads the same way a Finding run does, with the Asset surfaces in place of the Finding ones. The runs list's **Items Changed** and **Items Left Alone** counts link to the Assets list for an Asset run and to the Findings list for a Finding run, each filtered to exactly what that run touched or considered.

The left-alone list carries the same caveat it does for Findings: for a scheduled or manual sweep it is the rule's scope evaluated now, minus what the run changed. An Asset created since the run appears there, and one the run moved out of scope does not.

Every change an Asset rule makes is attributed to the rule, run and node that made it, and each Asset's own rules-engine history is available through the API at `/api/vue/rules_engine_v2/assets/{id}/provenance/`, the Asset twin of the Finding provenance timeline. Reading it follows Asset visibility: an Asset the caller cannot see answers 404 rather than an empty timeline.
