---
title: "Audit Logs"
description: "Access audit logs for DefectDojo objects"
weight: 1
---

Audit logs for DefectDojo can be accessed in a few different ways.

## Individual Object Logs
* DefectDojo objects each have an associated Object History, which can be accessed through the UI.  These histories are recorded for Products, Engagements, Tests, Findings and Endpoints, as well as Risk Acceptances.

In the Classic (Open-Source) UI, this history is found under the '☰' (hamburger) menu on an object.  In the Pro UI, this history is found under the blue '⚙️' (gear) menu for the object in question.

![image](images/view_history_ui.png)

## Object History Endpoint (Pro Only)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users have access to a `/history` API path for these objects to view similar data.  For example: `/api/v2/findings/{id}/history/`.

## Audit Log Endpoint (Pro Only)

<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users also have access to a dedicated `/audit_log` endpoint for their entire instance.  This log can only be accessed by users or API tokens with superuser permissions.

This API returns 31 days of audit logs.

* Sending default or empty parameters will return the last 31 days of audit logs.

* Parameter `window_month` which will take a month and year in the format MM-YYYY and provide the audit logs for that month.
* You can set the `window_start` parameter to limit these logs to a shorter window, rather than returning the entire month.

For more information, see the API documentation, located in your instance: `your-instance.cloud.defectdojo.com/api/v2/oa3/swagger-ui/`