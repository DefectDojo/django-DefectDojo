---
title: "Burp Suite Enterprise"
description: "How to set up the Burp Suite Enterprise Upstream Connector for DefectDojo"
weight: 30
audience: pro
---
DefectDojo’s Burp connector calls Burp’s GraphQL API to fetch data. 

#### Prerequisites

Before you can set up this connector, you will need an API key from a Burp Service Account. Burp user accounts don’t have API keys by default, so you may need to create a new user specifically for this purpose. 

See [Burp Documentation](https://portswigger.net/burp/documentation/enterprise/user-guide/api-documentation/create-api-user) for a guide on setting up a Service Account user with an API key.

#### Connector Mappings

1. Enter Burp’s root URL in the **Location** field: this is the URL where you access the Burp tool.
2. Enter a valid API Key in the Secret field. This is the API key associated with your Burp Service account.

See the official [Burp documentation](https://portswigger.net/burp/extensibility/enterprise/graphql-api/index.html) for more information on the Burp API.
