---
title: "Promptfoo"
description: "How to set up the Promptfoo Upstream Connector for DefectDojo"
weight: 107
audience: pro
---
The Promptfoo connector imports **LLM red-teaming and evaluation findings** from Promptfoo Cloud. DefectDojo creates a Record for each **target application** (provider) that Promptfoo probed.

#### Prerequisites

A Promptfoo Cloud **API token**, sent as a bearer token and never logged.

#### Connector Mappings

1. Enter `https://api.promptfoo.app` in the **Location** field.
2. Enter your Promptfoo API token in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo reads every stored evaluation the token can see and works out which targets were probed. A target's findings are its **failing** probes across all evaluations, aggregated **per weakness** rather than one finding per probe run — so repeated evaluations of the same weakness stay a single finding.
