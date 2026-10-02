---
title: "Intruder"
description: "How to set up the Intruder Upstream Connector for DefectDojo"
weight: 79
audience: pro
---
The Intruder connector uses the [Intruder REST API](https://developers.intruder.io/) to pull your whole account's posture into DefectDojo. Each Intruder **target** is discovered as a Record (Asset); each **occurrence** of an issue on a target becomes a Finding.

#### Connector Mappings

1. Leave the **Location** field as `https://api.intruder.io/` (the default Intruder API server).
2. Enter an Intruder **API access token** in the **Secret** field.

Generate an access token in Intruder under **My account > API Access Tokens** (you'll need your account password to create it, and the token is shown only once). See the [Intruder API documentation](https://developers.intruder.io/docs/creating-an-access-token) for details.

Findings are derived per occurrence: severity comes from the issue severity, CVEs and CVSS from the occurrence, the location from the target/port, and a snoozed occurrence is imported as an inactive (false-positive or risk-accepted) finding.
