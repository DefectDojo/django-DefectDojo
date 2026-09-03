---
title: "Akamai"
description: "How to set up the Akamai Upstream Connector for DefectDojo"
weight: 13
audience: pro
---
The Akamai API Security connector uses an API key to pull security findings from the Akamai API. DefectDojo will discover your Akamai environment and create separate Records for each **Application** and **Host** configured in your account.

#### Prerequisites

You will need an API key with access to the Akamai API. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions.

#### Connector Mappings

1. Enter your Akamai API base URL in the **Location** field. This URL is specific to your Akamai instance: for example
2. Enter a valid **API Key** in the **Secret** field.

DefectDojo will map **Applications** and **Hosts** as separate Records. Each Application will appear as `{name} (application)` and each Host as `{name} (host)` in your Records list.
