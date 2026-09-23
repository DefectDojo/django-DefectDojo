---
title: "Calico Cloud"
description: "How to set up the Calico Cloud Upstream Connector for DefectDojo"
weight: 31
audience: pro
---
The Calico Cloud connector imports **container image vulnerability findings** from Calico Cloud Image Assurance. DefectDojo creates a Record for each scanned **image repository**.

#### Prerequisites

An Image Assurance **API token**, from **Image Assurance \> Access Settings** in the Calico Cloud UI. This is the same token the `tigera-scanner` CLI uses, and it is never logged.

#### Connector Mappings

1. Enter your Image Assurance API URL in the **Location** field — the same value you would pass to `tigera-scanner` as `--apiurl`.
2. Enter the token in the **API Token** field.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each scanned image repository becomes a Record, carrying the CVE results of its images.

**Images whose scan results are not ready yet are skipped, not reported as clean.** Calico's registry scanner runs asynchronously, so an image can be absent from a Sync simply because its scan is still in progress — it will appear once results exist. This is worth knowing before reading a short finding list as a coverage gap.
