---
title: "Organizations"
description: "Understanding Organizations in DefectDojo Pro"
audience: pro
weight: 1
---
**ORGANIZATIONS** → Assets → Engagements → Tests → Findings

## Overview

**Organizations** sit at the very top of DefectDojo’s product hierarchy. Organizations are distinct from the descending objects in the hierarchy—Assets, Engagements, Tests, and Findings—because they are not technical scan targets, but rather serve primarily as organizational abstractions that compartmentalize your security efforts according to: 
- Business domain
- Development team
- Security team
- Software applications
- Overarching product family
- Customer or subsidiary
- Reporting structure
- etc. 

The theme of the above examples exemplifies the essential utility of Organizations: they should generally represent stable, long-lived boundaries within your security program.

## Organization Data and Structure

As Organizations are not scanned directly, the only mandatory field required to create them is a name. Beyond that, they act as containers for Assets and their descending Engagements, Tests, and Findings. 

When creating an Organization, consider how their structure will inform your reporting. Do you primarily need Organizations to represent the teams working on the projects (Assets) that Organizations will contain? Or would Organizations better represent overarching projects that contain different iterations of the projects (Assets) within it?

If you have a single Organization that contains all of the relevant information for a given business domain or development team, having that represented as an Organization will facilitate smoother reporting, rather than having to pull together a report from various Assets and Organizations. 

If a particular software project has many distinct deployments or versions, it may be worth creating a single Organization which covers the scope of the entire project and having each version exist as individual Assets. In some workflows, Organizations may also be used to separate software lifecycle stages: one Organization for “In Development,” one Organization for “In Production,” etc.
​
Organizations can be used to determine access to subsidiaries, acquired companies, or other regulated business units for RBAC purposes. In complex businesses, where there are a lot of unique projects with different access rules, Organizations are particularly relevant.

Ultimately, the decision of how to use Organizations and Assets depends on how you best wish to reflect your unique organizational structure and the needs of your security team. 

Below are some example structures to inform how you designate your objects as either Organizations or Assets. 

- **Organization**: Payments Division
    - Asset: Payments API - Production
    - Asset: Payments API - Staging
    - Asset: Billing Worker

- **Organization**: Software Product A
    - Asset: Web Portal
    - Asset: Mobile Backend

Additionally, the following is an illustrative guide as to whether a something is better represented by an Organization or an Asset: 

| Organizations | Assets |
|--------------|--------|
| Business units | Individual applications |
| Departments | Deployments/environments |
| Security ownership domains | Infrastructure components |
| Product families | Specific microservices |
| Portfolio-level reporting | Scan targets |
| Customers | Specific software versions |

As noted, your structure may differ depending on your unique security needs. 

## Accessing Organizations

Organizations are accessible via the sidebar. The submenu provides access to All Organizations as well as the option to create a new Organization.

![image](images/org_ss1.png)

## Organization View

An Organization’s view contains a variety of tables and charts to interpret its status at a glance. This includes: 

- **Description**
- **Commerce** 
    - Whether the Organization has been determined to be Critical or Key
        - Checking Critical or Key is used solely for filtering purposes 
- **Assigned Members** (DefectDojo Users)
- **Assigned User Groups** 
    - User groups that have been assigned to the Organization for permission control. More information about user groups can be found [here](/admin/user_management/create_user_group/). 
- **List of Assets within the Organization**

## Working with Organizations 

### Create Organizations 

There are two ways to create Organizations: 

- From the **New Organization** option in the side menu
- From the **New Organization** button at the top of the All Organizations list 

### Edit Organizations 

Organizations can be edited by clicking **Edit Organization** from within the gear menu at the top right of the Organization’s view. The same menu can also be accessed by clicking the ⋮ kebab menu to the left of the Organization in the All Organization view. 

All ensuing fields that can be edited are also available when the Organization is being created.

### Delete Organizations 

Deleting an Organization can be performed by selecting **Delete Organization** from the Organization’s settings. 

Because Organizations sit at the top of the hierarchy, deleting them removes all downstream security history, relationships, and child objects, such as: 
- Any Assets, Engagements, and Tests contained within the Organization
- All associated security history, including Findings and integrations
- Any linked Jira Epics
- All notes and file uploads associated with the Assets, Engagements, and Tests within that Organization

Deleting an Organization can’t be undone. If you would like to “decommission” an organization without deleting underlying data (for example, preserving legacy software testing records for audit purposes), you can change the Organization’s name or add a Tag to indicate that it is in a deprecated state.

## Organiations vs. Metadata 

Organizations are intended to represent structural ownership or reporting boundaries, rather than lightweight classifications. Attributes such as deployment status, internal labels, or temporary workflow states may be better represented through tags or metadata rather than separate Organizations.

## Organization Boundaries 

Organizations establish both reporting and access boundaries within DefectDojo. Because integrations, RBAC permissions, ownership, metrics, and deduplication models frequently inherit Organizations’ structure, designing clear boundaries early helps avoid hierarchy sprawl and reporting fragmentation later.

### Findings and Automation 

Although integrations are typically configured on lower-level objects such as Assets, Engagements, or Findings, Organizations still define the ownership, reporting, and access boundaries within which those integrations operate.

Permissions cascade downward, meaning that access to an Organization automatically grants access to all objects within that Organization (e.g., Assets, Engagements, Tests, and Findings). 

The DefectDojo RBAC model can be used to gate human user access, but can also restrict API tokens’ access to particular Organizations.

For more information on user roles, see our [Introduction To Permission Types](/admin/user_management/set_user_permissions/#introduction-to-permission-types) article.

### Ownership

As top-level objects, Organizations also imply ownership over the child objects within them. SLA tracking, remediation workflows, ticket routing, and general governance all flow more smoothly when Organizations have been set up to accurately reflect the individuals accountable for them.

### Metrics/Reporting 

Metrics dashboards, tiles and views can be filtered per Organization, making them a critical component in how your security data is calculated, visualized, and ultimately exported. 

For reporting purposes, it is generally easier to combine multiple Organizations into a single document than it is to subdivide a single Organization into separate documents. Therefore, we recommend setting up Organizations at as granular a level as makes sense for your team’s reports. For example, there is no need to represent a large business division as an Organization if you’re primarily going to be reporting to individual departments within that division.

Effectively structuring your Organizations to reflect your reporting needs is critical to accurately assessing your security posture. For more information on Metrics, click [here](/metrics_reports/pro_metrics/pro__overview/).

### Deduplication

Deduplication in DefectDojo occurs at the Asset level, and is not affected by the parent Organization.