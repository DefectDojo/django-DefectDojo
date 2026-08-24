---
title: "Wazuh"
description: "How to set up the Wazuh Upstream Connector for DefectDojo"
weight: 140
audience: pro
---
The Wazuh connector uses the Wazuh Indexer (OpenSearch) to fetch vulnerability findings. Wazuh 4.8 and later store detected CVEs in the Indexer rather than the Wazuh server API, so this connector reads them directly from the `wazuh-states-vulnerabilities-*` index.

DefectDojo creates a Record for each Wazuh agent (endpoint) and imports that agent's detected CVEs as findings on a scheduled basis.

#### Prerequisites

You will need:

* The base URL of your Wazuh Indexer, including the port (the Indexer listens on port 9200 by default). DefectDojo connects to the Indexer directly, so this endpoint must be reachable from DefectDojo. For self\-managed deployments this is the host running the Wazuh Indexer. For Wazuh Cloud, use the Indexer endpoint shown in your Wazuh Cloud console, which is separate from the Wazuh dashboard URL.
* An Indexer user and password with read access to the `wazuh-states-vulnerabilities-*` index. We recommend creating a dedicated user for DefectDojo.

Vulnerability detection must be enabled in Wazuh so that the vulnerability\-state index is populated. See the [Wazuh vulnerability detection documentation](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) for more information.

#### Connector Mappings

1. Enter your Wazuh Indexer base URL in the **Location** field, including the scheme and port, for example `https://your-indexer.example.com:9200`. Do not include a trailing path. DefectDojo constructs the search paths automatically.
2. Enter the Indexer username in the **Username** field.
3. Enter the Indexer password in the **Password** field.
4. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.
