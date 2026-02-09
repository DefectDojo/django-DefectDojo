---
title: "SLA Configuration"
description: "Configure Service Level Agreements for different Products"
weight: 2
audience: opensource
aliases:
  - /en/working_with_findings/sla_configuration
---
Each Product in DefectDojo can have its own Service Level Agreement (SLA) configuration, which represents the days your organization has to remediate or otherwise manage a Finding.

SLA can be set based on either **[Finding Severity](/asset_modelling/hierarchy/product_hierarchy/#findings)** or **[Finding Risk](/asset_modelling/hierarchy/pro__priority_sla/)** (in DefectDojo Pro).

![image](images/sla_multiple.png)

SLAs apply a countdown of days to a Finding based on the day that the Finding was created in DefectDojo.  If a Finding is not Closed within the countdown, the Finding will be labeled as in breach of SLA.

## Working with SLAs

You can use SLAs as a way to represent your organizations remediation policies.  You can also use them as a way to prioritize the longest-active, most critical Findings in your DefectDojo instance.  

* You can sort or filter Finding tables by SLA days.
* SLA violations can be configured to trigger [Notifications](/admin/notifications/about_notifications/) to DefectDojo users assigned to the related Product.
* In **DefectDojo Pro**, SLA performance is also tracked on the [Executive Insights and Remediation](/metrics_reports/pro_metrics/pro__overview/) Metrics Dashboards.
* SLA compliance can also be used to create custom [Dashboard Tiles](/metrics_reports/dashboards/about_custom_dashboard_tiles/#sla-violation-tile) in **DefectDojo Pro**.

### Mitigated Within SLA status

If a Finding is successfully Mitigated by the SLA deadline, the Finding will record a ✅ green check mark in the Mitigated Within SLA column.

![image](images/sla_mitigated_within.png)

If a Finding was Mitigated, but not before the SLA was violated, the Finding will record a ❌ red X in the Mitigated Within SLA column.

### Breaching SLAs

When an SLA for a given Finding is violated (the Finding is not Closed within the SLA timeline) the ✅ green check will switch to a ❌ red X.  The SLA will continue to be tracked with a negative number, to represent how many days the SLA has been breached by.

![image](images/sla_breached.png)

## Managing SLA Configurations (Pro)

In DefectDojo Pro, one or more SLA Configurations are managed under the **Configuration > Service Level Agreements** part of the sidebar.  You can create a **New Service Level Agreement** or work with existing SLA configurations from the **All Service Level Agreements** page.

![image](images/pro_sla_risk.png)

SLA Configurations can only be edited by Superusers or by a user with the corresponding [Configuration Permission](/admin/user_management/user_permission_chart/#configuration-permission-chart).

### Configuring SLA

SLA configurations contain the days assigned to each **Severity** or **Risk** value of DefectDojo.

![image](images/pro_new_sla.png)

Each Service Level Agreement can have a unique name, along with an optional description.

**Restart SLA on Finding Reactivation**: if enabled, this option will start an SLA over when a Finding is Reopened.  Otherwise, the SLA will be based on when the Finding was created.

When editing an SLA, you can choose whether that SLA will use **Severity** or **Risk** as a benchmark for assigning Days To Remediate.  This is done by selecting the related option from the **Service Level configuration Type** section of the form.

From here, you can set the number of days allowed for each **Severity** or **Risk** level.  You can also selectively enforce SLAs; by unchecking the **Enforce ___ Finding Days** you can ignore SLA calculation for those levels of Severity or Risk.

## Apply an SLA Configuration to a Product (Pro)

Newly created Products in DefectDojo will always apply the **Default SLA Configuration**, which can be set to different values if you wish.

If you have SLA configurations, you can choose which of these is applied to your Product from the **Edit Product** form.  

![image](images/pro_sla_product.png)

### SLA Recalculation

Once a new SLA has been selected for a Product, all of the associated Findings' SLAs will need to be recalculated by DefectDojo.  While this process is running, a Product's SLA cannot be changed.

## Notes on SLAs

* SLAs can be optionally restarted once a [Risk Accepted](/triage_findings/findings_workflows/risk_acceptances/) Finding reactivates.  This is set when creating the Risk Acceptance by setting the **Restart SLA Expired** field.
* Reimporting a Finding does not restart the SLA - SLAs are always calculated from when a Finding was first detected unless **Restart SLA on Finding Reactivation** is enabled.
* Risk Acceptance expiry or reactivation of a Closed Finding are the only ways to reset or recalculate an SLA for a Finding once it is created (without changing the Product's SLA configuration).
