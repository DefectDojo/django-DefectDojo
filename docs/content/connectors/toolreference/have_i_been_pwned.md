---
title: "Have I Been Pwned"
description: "How to set up the Have I Been Pwned Upstream Connector for DefectDojo"
weight: 72
audience: pro
---
The Have I Been Pwned (HIBP) connector uses the HIBP REST API to report which accounts on your organization's own domains have appeared in known data breaches. DefectDojo discovers each domain you have verified with HIBP and imports one finding per breach affecting that domain.

#### Prerequisites

You will need a Have I Been Pwned API key with domain search, which requires a **Core** subscription tier or higher. You can obtain a key from your [Have I Been Pwned account](https://haveibeenpwned.com/API/Key).

You must also **verify at least one domain** on your HIBP account before any breach data is available. HIBP lets you verify a domain by DNS TXT record, meta tag, file upload, or email, under **Domain search** in your account. Until a domain is verified, the connector discovers no domains and imports no findings.

#### Connector Mappings

1. Enter `https://haveibeenpwned.com` in the **Location** field.
2. Enter your API key in the **Secret** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported. Findings below the selected severity will not be imported.

DefectDojo creates a separate Record for each domain you have verified with HIBP, and imports one finding per breach affecting accounts on that domain. Each finding's severity reflects the kind of data the breach exposed, and its description lists the affected accounts on your domain so your team can act on them.

See the [Have I Been Pwned API documentation](https://haveibeenpwned.com/API/v3) for more information.
