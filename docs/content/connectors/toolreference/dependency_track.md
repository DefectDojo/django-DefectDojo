---
title: "Dependency-Track"
description: "How to set up the Dependency-Track Upstream Connector for DefectDojo"
weight: 48
audience: pro
---
This connector fetches data from a on\-premise Dependency\-Track instance, via REST API.

​**Connector Mappings**

1. Enter your local Dependency\-Track server URL in the **Location** field.
2. Enter a valid API key in the **Secret** field.

To generate a Dependency\-Track API key:

1. **Access Management**: Navigate to Administration \> Access Management \> Teams in the Dependency\-Track interface.
2. **Teams Setup**: You can either create a new team or select an existing one. Teams allow you to manage API access based on group membership.
3. **Generate API Key**: In the selected team's details page, find the "API Keys" section. Click the \+ button to generate a new API key.
4. **Assign Permissions**: In the "Permissions" section of the team's page, click the \+ button to open the permissions selector. Choose **VIEW\_PORTFOLIO** and **VIEW\_VULNERABILITY** permissions to enable API access to project portfolios and vulnerability details.
5. Click "**Select**" to confirm and save these permissions.

For more information, see **[Dependency\-Track Documentation](https://docs.dependencytrack.org/integrations/rest-api/)**.
