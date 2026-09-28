---
title: "InsightCloudSec"
description: "How to set up the InsightCloudSec Upstream Connector for DefectDojo"
weight: 77
audience: pro
---
The InsightCloudSec connector imports **cloud security posture findings** from Rapid7 InsightCloudSec. DefectDojo creates a Record for each **onboarded cloud account**.

**Please note:** InsightCloudSec (formerly DivvyCloud) is a **distinct Rapid7 product** from InsightVM and InsightAppSec, each of which has its own connector in this list. Make sure you are configuring the one that matches your Asset.

#### Prerequisites

An InsightCloudSec **API key**, from the **API Keys** page in your user profile. It is never logged.

#### Connector Mappings

1. Enter `https://cloudsec.insight.rapid7.com` in the **Location** field. Self\-hosted InsightCloudSec deployments use their own host.
2. Enter the API key in the **API Key** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

One finding is created per **insight and failing resource** pair, so a single policy failing across many resources produces a finding for each — grouped under the cloud account the resource belongs to.
