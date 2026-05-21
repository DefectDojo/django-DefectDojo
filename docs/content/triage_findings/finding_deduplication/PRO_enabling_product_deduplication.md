---
title: "Enabling Deduplication"
description: "How to enable Deduplication at the Product or Engagement level"
weight: 2
audience: pro
aliases:
  - /en/working_with_findings/finding_deduplication/enabling_product_deduplication
---
Deduplication can be applied at a Product\-wide level, or scoped more narrowly to a single Engagement.

## Deduplication for Products

1. Navigate to the System Settings page: **Settings \> Pro Settings \> ⚙️ System Settings** on the sidebar.

![image](images/enabling_product-level_deduplication.png)

2. The **Deduplication and Finding Settings** card is at the top of the **System Settings** page.

![image](images/enabling_product-level_deduplication_2.png)

### Enable Finding Deduplication

**Enable Finding Deduplication** turns on the Deduplication Algorithm for all Findings. Once enabled, Deduplication runs on every subsequent import — DefectDojo compares imported Findings against existing Findings in the destination Product and marks duplicates according to your configuration.

### Delete Duplicate Findings

**Delete Duplicate Findings**, combined with the **Maximum Duplicates** field, limits how many duplicate Findings DefectDojo retains. When enabled, a background job periodically prunes excess duplicates so that each original Finding keeps no more than the configured **Maximum Duplicates** count. Oldest duplicates are removed first.

## Deduplication for Engagements

Rather than Deduplicating across an entire Product, you can scope Deduplication to a single Engagement.

### Open the Engagement form

* **For a new Engagement:** open the **📥 Engagements** sub‑menu on the sidebar and click **\+ New Engagement**.

![image](images/enabling_deduplication_within_an_engagement.png)

* **For an existing Engagement (from the All Engagements page):** open the **⋮** menu for the Engagement and select **Edit Engagement**.

![image](images/enabling_deduplication_within_an_engagement_2.png)

* **For an existing Engagement (from the Engagement page):** open the **⚙️ Gear** menu in the top‑right corner of the page and select **Edit Engagement**.

![image](images/enabling_deduplication_within_an_engagement_3.png)

### Completing the Engagement form

1. On the Engagement form, locate the ☐ **Isolate Deduplication from Other Engagements** checkbox. It appears above the **Optional Fields \+** panel.
2. Check the box to scope Deduplication to this Engagement.
3. Submit the form.

When this option is enabled, Findings in this Engagement will only be deduplicated against other Findings within the same Engagement. Findings in other Engagements on the same Product are ignored by the Deduplication Algorithm.

![image](images/enabling_deduplication_within_an_engagement_4.png)
