---
title: "Threat Modeling"
description: "Generate a threat model, attack paths and security requirements from a feature design, before the code exists"
draft: false
audience: pro
weight: 5
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Threat Modeling is a DefectDojo Pro-only feature and is currently in BETA.</span>

**Threat Modeling** turns a feature design into a reviewed threat model. You supply the design — pasted text, a design document, and optionally an architecture diagram — and DefectDojo produces the components and data flows it describes, the threats against them, and the security requirements that mitigate those threats. Requirements can then be pushed into DefectDojo as findings, so design-stage work flows through the same triage, SLA, Jira and reporting machinery as everything else.

This is Sensei's **pre-code** capability. Where [scan-and-fix](/sensei/about_sensei/) works on a repository that already exists, threat modeling works on the design, before there is code to scan.

> **🔎 BETA:** Threat Modeling is under active development and is labeled **BETA** throughout the UI. Behavior and screens may change between releases. It is on by default; a superuser can switch it off, or back on, from the [Feature Flags page](/admin/feature_flags/pro__feature_flags/) — no Support request is required.

> **📍 Where to find it:** open **Threat Modeling** from the left-hand navigation, directly below Sensei.

## What you need

- The **Sensei** licensed feature. Threat modeling ships under the same entitlement as scan-and-fix.
- The **AI Threat Modeling** feature flag, which is on by default. If your instance turned it off, a superuser can turn it back on from the [Feature Flags page](/admin/feature_flags/pro__feature_flags/).
- A global **Maintainer** or **Owner** role. Users without it do not see the page.
- An Asset to attach the threat model to. Instances that have not enabled 3.0 naming see Assets called **products**; this page says *Asset* throughout, and the UI follows whichever naming your instance is set to.

Nothing is installed and no repository is connected. Threat modeling reads only the design you supply.

## Generating a threat model

Choose **New threat model**, pick the Asset, give it a name, and supply the design in whichever form you have it:

- **Paste the description** directly, or
- **Upload a design document** — `.md`, `.markdown`, `.txt`, `.text` or `.pdf`. Text extraction from PDF is best-effort; if a PDF is mostly images, paste the text instead.
- **Optionally add an architecture diagram** — PNG, JPEG, WebP or GIF. The diagram is read alongside the text, so a component that only appears in the picture is still picked up.

You can combine them: a short pasted summary plus a diagram often produces a better model than either alone.

Generation runs in the background and moves through four stages, shown on the run as it progresses:

1. **Extracting architecture** — components, trust boundaries, data assets and data flows.
2. **Enumerating threats** — threats per STRIDE category.
3. **Writing security requirements** — testable requirements, each tied to the threats it mitigates.
4. **Assembling results** — the diagram and final consistency checks.

A run typically takes several minutes. You can leave the page; progress and results are kept on the run.

## Reading the results

### Architecture

The **Architecture** tab renders what was extracted as a data-flow diagram: components grouped by trust boundary, with flows labeled by protocol. Flows that **cross a trust boundary** are drawn differently, because those are the interesting ones. Selecting a component shows the threats that target it.

The model also records what it could **not** determine — assumptions it had to make, and points that were unclear in the design. Read these first: they tell you where the design itself is ambiguous, which is often the most useful output of the exercise.

### Threats

Each threat carries:

- Its **STRIDE category** (spoofing, tampering, repudiation, information disclosure, denial of service, elevation of privilege) and a **severity**.
- The **attacker profile** — for example an external unauthenticated attacker, an insider, or a supply-chain compromise — and the skill required.
- An ordered **attack path**: the steps an attacker would take, with prerequisites.
- A **CWE**, where one applies, drawn from a fixed list rather than invented.
- The **components, flows and data assets** it targets.

### Security requirements

Each requirement is written as a testable statement, with a **verification** step describing how to confirm it holds, a category (authentication, authorization, input validation, cryptography, and so on), and a priority. Every requirement names the threats it mitigates.

Coverage is accounted for explicitly: a threat is either mitigated by at least one requirement or listed as a **coverage gap**. Gaps are shown rather than hidden, so a threat is never silently dropped.

## Evidence, and what to trust

Every component, threat and requirement carries the **evidence** it came from, and evidence is labeled by source:

- **From the design text** — a quote that was matched, word for word, against the text you supplied.
- **From the diagram** — read from the image, so there is no text to quote.
- **Inferred** — not stated in the design at all.

A quote that could not be matched against the supplied text is kept but **flagged as unverified**, with the claimed quote shown so you can judge it yourself. Items are flagged rather than removed, because a silently discarded threat is a risk nobody hears about. Structurally broken items — a threat referencing a component that was never extracted — are dropped, and the count of what was dropped is recorded on the run.

**Treat the output as a draft for review, not a finished artifact.** It is generated from a design document by a language model; the evidence labels exist so you can see which parts are grounded in what you wrote and which are inference.

## Pushing requirements into findings

Requirements become actionable through **Push to findings**. Select the requirements you want and DefectDojo creates one finding per requirement, in a dedicated engagement named **Sensei Threat Modeling** on that Asset, with one test per threat-model version.

Each finding carries:

- The requirement statement, plus the narrative of every threat it mitigates — STRIDE category, attacker, and the numbered attack path — so whoever picks up the ticket has the context without opening the threat model.
- The verification step as the mitigation.
- The requirement's severity and CWE.
- The tag `sensei-threat-model`, a `tm-v<version>` tag, and a STRIDE tag.

Findings are created **active but not verified**: a generated requirement is a proposal for a human to confirm.

Pushing is **idempotent**. Each requirement owns its finding, so pushing the same model again updates in place instead of creating duplicates — and if you edit a requirement and push again, the finding follows. Re-pushing does not rewrite who first raised the finding.

## Versions and supersession

Threat models are **versioned per Asset**. Regenerating from an updated design creates a new version rather than overwriting the old one, so you keep the history of what the design looked like when a decision was made.

When you push a newer version, findings from the previous version that no longer correspond to a current requirement are **mitigated** rather than left open, so the engagement reflects the current design.

## Exporting

A threat model can be downloaded as **Markdown** for a design review or ticket, or as **JSON** for anything programmatic. Both are available from the threat model itself.

## Generation activity

The **Activity** tab lists every generation, its status and the stage it reached. Runs in progress can be **cancelled**. A failed run shows **why** it failed — a configuration problem, an input that was too long, or a temporary service error — and completed stages are checkpointed, so retrying resumes rather than starting from the beginning.

## Costs

Threat modeling calls a large language model, and each generation has a cost. A generation makes roughly eight calls, and usage is recorded per run alongside Sensei's other LLM usage, so you can see what a model cost to produce. Cancelling a run stops further calls at the next stage boundary.
