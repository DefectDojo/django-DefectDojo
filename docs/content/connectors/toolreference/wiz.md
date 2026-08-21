---
title: "Wiz"
description: "How to set up the Wiz Upstream Connector for DefectDojo"
weight: 142
audience: pro
---
Using the Wiz connector requires you to create a service account: see the [Wiz documentation](https://docs.wiz.io/wiz-docs/docs/service-accounts-settings#add-a-service-account) for more info.  You will need a Wiz account to access the documentation.

The service account must meet all of the following requirements. A service account that misses one of them can still authenticate successfully but will import nothing:

* **Type**: Custom Integration (GraphQL API).
* **API scopes**: at minimum `read:projects`, `read:issues`, and `read:vulnerabilities`.
* **Project visibility**: the service account must be scoped to every Wiz Project you want imported (or to all Projects). The connector discovers your Wiz Projects first and then pulls each Project's findings — an account that can read issues but has no Project visibility discovers zero Projects, so there is nothing to import and no error is reported by either side.

#### **Connector Mappings**

1. Enter your Wiz Client ID in the Client ID field.
2. Enter the Wiz Client Secret in the Secret field.
