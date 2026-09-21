---
title: "Elastic Security"
description: "How to set up the Elastic Security Upstream Connector for DefectDojo"
weight: 53
audience: pro
---
The Elastic Security connector imports **cloud vulnerability, posture and detection findings** from an Elasticsearch cluster, as three separate finding types. DefectDojo creates a Record for each **cloud account**.

Not every Elastic finding carries a cloud account, so DefectDojo falls back in order: the **Kubernetes cluster** (for KSPM findings with no cloud account), then the **host**. Anything identifying none of those lands in a single catch\-all Record rather than being dropped.

#### Prerequisites

An Elasticsearch **API key**, supplied as the base64 `id:api_key` value.

**Prefer an API key over a username and password**, because a key can be scoped read\-only to just the security indices. A username and password are supported as a fallback for clusters that do not have API keys enabled.

#### Connector Mappings

1. Enter your Elasticsearch cluster URL in the **Location** field.
2. Enter the base64 API key in the **API Key** field. Leave it blank if you are using a username and password instead.
3. If you are not using an API key, enter the **Username** and password for HTTP Basic authentication. These are only used when no API key is supplied.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.
