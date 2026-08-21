---
title: "Alert Logic"
description: "How to set up the Alert Logic Upstream Connector for DefectDojo"
weight: 15
audience: pro
---
The Alert Logic connector imports **vulnerability exposures** from your Alert Logic account. DefectDojo creates a Record for each Alert Logic **deployment**, with no per\-deployment configuration required.

#### Prerequisites

An Alert Logic **access key ID and secret key**, created under **Configure \> API Keys**. DefectDojo exchanges them for a short\-lived session token on each Sync; neither the secret nor the token is ever logged.

#### Connector Mappings

1. Enter your region's API URL in the **Location** field — `https://api.cloudinsight.alertlogic.com` (US) or `https://api.cloudinsight.alertlogic.co.uk` (UK). Alert Logic is region\-partitioned, so this must match the region your account lives in.
2. Enter the access key ID in the **Access Key ID** field.
3. Enter the secret in the **Secret Key** field.
4. Optionally, enter an **Account ID** to override the account the credentials authenticate into. This is intended for managed\-service parent accounts operating on a child account.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

This connector imports **vulnerability exposures only** — MDR incidents are deliberately out of scope.
