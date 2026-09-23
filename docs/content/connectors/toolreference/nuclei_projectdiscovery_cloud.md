---
title: "Nuclei (ProjectDiscovery Cloud)"
description: "How to set up the Nuclei (ProjectDiscovery Cloud) Upstream Connector for DefectDojo"
weight: 97
audience: pro
---
The Nuclei connector uses the ProjectDiscovery Cloud Platform (PDCP) REST API to pull [nuclei](https://github.com/projectdiscovery/nuclei) scan results from your PDCP account. DefectDojo discovers every scan in the account and creates a separate Record for each **scan**.

#### Prerequisites

You will need a ProjectDiscovery Cloud **API key**. We recommend creating a dedicated service account for DefectDojo to clearly distinguish automated activity from manual team actions. Generate a key from **Settings \> API Key** in the ProjectDiscovery Cloud UI ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Results reach PDCP either from hosted scans or from the nuclei CLI run with `-dashboard`.

#### Connector Mappings

1. Enter the PDCP API base URL in the **Location** field: `https://api.projectdiscovery.io`.
2. Enter your **API key** in the **Secret** field.
3. Optionally, enter a **Team ID** to scope the sync to a team workspace (found under **Settings \> Team**). When left blank, DefectDojo syncs your personal workspace.
4. Optionally, set a **Minimum Severity** to limit which findings are imported.

DefectDojo maps each PDCP **scan** as a separate Record and imports that scan's findings across every severity, including informational.
