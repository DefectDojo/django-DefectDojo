---
title: "Anchore Enterprise"
description: "How to set up the Anchore Enterprise Upstream Connector for DefectDojo"
weight: 16
audience: pro
---
The Anchore connector uses a user's API token to pull data from Anchore Enterprise.  Assets will be mapped and discovered based on "Applications", which are composed of multiple Images in Anchore - see [Anchore Enterprise Documentation](https://docs.anchore.com/current/docs/sbom_management/application_groups/application_management_anchorectl/) for more information.

#### Connector Mappings

1. The Anchore URL in the **Location** field: this is the URL where you access the Anchore.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Anchore documentation](https://docs.anchore.com/current/docs/) for more information on creating a token for Anchore.
