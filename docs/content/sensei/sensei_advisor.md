---
title: "Sensei Advisor"
description: "Let Sensei analyze your instance and recommend deduplication and prioritization settings you review and apply."
draft: false
audience: pro
weight: 5
---

**Sensei Advisor** looks at how your instance is configured and what your data looks like, and
proposes concrete settings changes for you to review and apply. It never changes anything on
its own: every recommendation is applied by a person, in one click, and can be reverted.

The first release covers three areas:

- **Cross-tool deduplication.** Cross-tool matching ships turned off and empty, and two tools
  only ever deduplicate against each other when both are configured with the *identical*
  ordered list of hash fields. Getting that right by hand means knowing which of your tools
  report the same vulnerabilities and which fields are stable across them. The Advisor groups
  the tools that overlap and proposes one shared field list per group.
- **Deduplication hygiene.** Deterministic checks (no AI involved) that surface configuration
  that quietly breaks deduplication: a field list that silently falls back to the legacy hash,
  a dead entry for a tool nothing produces, a field that cannot be declared. Two of these
  carry a one-click fix, because they have exactly one correct remediation: a **dead entry**
  can be removed (nothing produces the tool, so no finding's hash changes), and
  **undeclarable fields** can be pruned so the rest of the configured list takes effect
  (this rehashes the affected tool's findings). Both fixes capture the previous
  configuration and can be reverted in one step, and both require the same permission as
  editing the deduplication settings by hand. Everything else appears as an informational
  card.
- **Prioritization engine.** Given how your findings are distributed across the risk bands and
  which scoring inputs your data actually populates, the Advisor proposes a tuned engine
  configuration.

## What the model is shown — and what it is not

Sensei Advisor is built around a strict data-minimization rule: the model is shown your
**configuration and aggregate statistics only** — the names of your tools and fields, counts,
and the percentage of findings that carry each field. It is **never** shown the contents of
individual findings: no titles, descriptions, file paths, or values. This is enforced in code
by an allowlist check over everything assembled for the model, so a finding's content cannot
reach it.

You, reviewing a recommendation, do see your own example values, so you can judge a proposal
the model made from statistics alone.

## Reviewing and applying

Each analysis produces a set of recommendations grouped by area. Every card shows the
rationale, the statistics that support it, and a **simulated impact** measured against a sample
of your real findings — for a cross-tool group, roughly how many finding pairs the change would
merge, and which tool pairs they fall between. A recommendation whose simulated effect is
essentially zero is flagged rather than presented as confident, and one that would collapse
unrelated findings onto a single hash is dropped before you ever see it.

Applying a recommendation uses the same settings machinery and permissions as changing the
setting by hand — applying a deduplication recommendation requires the Tuner edit permission,
and creating a prioritization engine requires the engine permission. The Advisor grants no new
power; it drives the controls you already have.

### Rehash cost

Applying a cross-tool recommendation recomputes the cross-tool hash for every finding of the
affected tools, in the background. The card shows an estimate of how many findings that is.
Large tools take longer; the work runs in the background and does not block the instance.

### Reverting

Applying records the previous configuration, so any applied recommendation can be reverted in
one click. Reverting restores the prior settings and re-runs the same background recompute. A
prioritization recommendation creates a *new* engine rather than editing an existing one, so it
is reverted by removing that engine (only possible while no products are assigned to it).

## Availability

Sensei Advisor is part of Sensei and requires a Sensei-enabled license. On self-hosted
installations without cloud AI, configure a provider under **AI Model Settings**. The feature
is in beta and enabled per instance by DefectDojo.
