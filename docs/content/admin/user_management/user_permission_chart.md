---
title: "Action permission charts"
description: "All DefectDojo Pro user permissions in detail"
weight: 4
audience: pro
aliases:
  - /en/customize_dojo/user_management/user_permission_chart
---

> **DefectDojo Pro feature.** The Members / Groups / Global Roles RBAC system described on this page is part of DefectDojo Pro. Open-source DefectDojo uses the [Authorized Users](../os__authorized_users/) model — see that page for open-source access control, and the [3.0 upgrade notes](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) if you're moving between editions.

## Role Permission Chart

This chart is intended to list all permissions related to an Asset or Organization, as well as which permissions are available to each role.

The five roles below are DefectDojo Pro's **built-in roles**. They are locked presets: their permissions are the same on every instance and cannot be changed. If you have built your own roles, this chart describes the built-ins they were cloned from rather than the roles themselves. For the full catalog of permissions a role can be given, see [Custom RBAC Roles](../pro__custom_rbac_roles/#choosing-permissions).

| **Section** | **Permission** | Reader | Writer | Maintainer | Owner | API Importer |
| --- | --- | --- | --- | --- | --- | --- |
| **Asset / Organization Access** | View assigned Asset or Organization ¹ | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | View nested Assets, Engagements, Tests, Findings, Endpoints | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Add new Assets (within assigned Organization) ² |  |  | ☑️ | ☑️ |  |
|  | Delete assigned Assets or Organizations |  |  |  | ☑️ |  |
| **Asset / Organization Membership** | Add Users as Members (excluding Owner Role) |  |  | ☑️ | ☑️ |  |
|  | Edit member Roles (excluding Owner Role) |  |  | ☑️ | ☑️ |  |
|  | Edit member Roles (including Owner Role) |  |  |  | ☑️ |  |
|  | Remove self from Asset / Organization membership | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Add an Owner Role to another User |  |  |  | ☑️ |  |
|  | Edit an associated Asset/Organization Membership within a Group³ |  |  |  | ☑️ |  |
|  | Delete an associated Asset/Organization Membership within a Group³ |  |  |  |  |  |
| **Engagements** (Within an Asset) | Add, Edit Engagements |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | View Risk Acceptances ⁴ |  | ☑️ | ☑️ | ☑️ |  |
|  | Add, Edit Risk Acceptances |  | ☑️ | ☑️ | ☑️ |  |
|  | Delete Engagements |  |  | ☑️ | ☑️ |  |
| **Tests** (Within an Asset) | Add Tests |  | ☑️ | ☑️ | ☑️ |  |
|  | Edit Tests |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Delete Tests |  |  | ☑️ | ☑️ |  |
| **Findings**  (Within an Asset) | Add Findings |  | ☑️ | ☑️ | ☑️ |  |
|  | Edit Findings |  | ☑️ | ☑️ | ☑️ |  |
|  | Import, Reimport  Scan Results |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Delete Findings |  |  | ☑️ | ☑️ |  |
|  | Add, Edit, Delete  Finding Groups |  | ☑️ | ☑️ | ☑️ |  |
| **Other Data**  (Within an Asset) | Add, Edit Endpoints |  | ☑️ | ☑️ | ☑️ |  |
|  | Delete Endpoints |  |  | ☑️ | ☑️ |  |
|  | Edit Benchmarks |  | ☑️ | ☑️ | ☑️ |  |
|  | Delete Benchmarks |  |  | ☑️ | ☑️ |  |
|  | View Note History | ☑️ | ☑️ | ☑️ | ☑️ |  |
|  | Add, Edit, Delete Own Notes | ☑️ | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Edit Other Notes |  | ☑️ | ☑️ | ☑️ | ☑️ |
|  | Delete Other Notes |  |  | ☑️ | ☑️ |  |

1. A user who is assigned permissions at the Asset level only cannot view the Organization it is contained in.
2. When a new Asset is added underneath an Organization, all Organization\-level Users will be added as Members of the new Asset with their Organization\-level Role.
3. The user who wishes to make changes to a Group must also have **Edit Group** **Configuration Permissions**, and a **Maintainer or Owner** **Group Configuration Role** in the Group they wish to edit.
4. Risk Acceptance visibility is gated by a distinct minimum permission from Finding visibility — a Reader on the Asset can view the underlying Findings but **cannot** view Risk Acceptances those Findings belong to.  For details on Risk Acceptance permissions, expiration-date behavior, and reinstate workflows, see [Risk Acceptances (Pro)](/triage_findings/findings_workflows/pro__risk_acceptance/#risk-acceptance-permissions-and-visibility).

## Configuration Permission Chart

Each Configuration Permission refers to a particular function in the software, and has an associated set of actions a user can perform related to this function.

The majority of Configuration Permissions give users access to certain pages in the UI. 

| **Configuration Permission** | **View ☑️** | **Add ☑️** | **Edit ☑️** | **Delete ☑️** |
| --- | --- | --- | --- | --- |
| Credential Manager | Access the **⚙️Configuration \> Credential Manager** page | Add new entries to the Credential Manager | Edit Credential Manager entries | Delete Credential Manager entries |
| Development Environments | n/a | Add new Development Environments to the 🗓️**Engagements \> Environments** list | Edit Development Environments in the 🗓️**Engagements \> Environments** list | Delete Development Environments from the **🗓️Engagements \> Environments** list |
| Finding Templates¹ | Access the **Findings \> Finding Templates** page | Add a Finding Template | Edit a Finding Template | Delete a Finding Template |
| Groups | Access the **👤Users \> Groups** page | Add a new User Group | Superuser only | Superuser only |
| Jira Instances | Access the **⚙️Configuration \> JIRA page** | Add a new JIRA Configuration | Edit an existing JIRA Configuration | Delete a JIRA Configuration |
| Language Types |  |  |  |  |
| Login Banner | n/a | n/a | Edit the login banner, located under **⚙️Configuration \> Login Banner** | n/a |
| Announcements | n/a | n/a | Configure Announcements, located under  **⚙️Configuration \> Announcements** | n/a |
| Note Types | Access the ⚙️Configuration \> Note Types page | Add a Note Type | Edit a Note Type | Delete a Note Type |
| Prioritization Engines | Access the Prioritization Engine configuration page | Add a new Prioritization Engine | Edit an existing Prioritization Engine | Delete a Prioritization Engine |
| Organizations | n/a | Add a new Organization (under Assets \> Organization) | n/a | n/a |
| Questionnaires | Access the **Questionnaires \> All Questionnaires** page | Add a new Questionnaire | Edit an existing Questionnaire | Delete a Questionnaire |
| Questions | Access the **Questionnaires \> Questions** page | Add a new Question | Edit an existing Question | n/a |
| Regulations | n/a | Add a Regulation to the **⚙️Configuration \> Regulations** page | Edit an existing Regulation | Delete a Regulation |
| Rules Engine | Access the **Rules Engine 2.0** sidebar section and everything under it (All Rules, Runs, and Deliveries) | Create a rule, including converting one from the original Rules Engine | Change, enable, schedule, run, replay, or take ownership of an existing rule | Delete a rule |
| Scheduling Service Schedule | Access the **Scheduling** page | Superuser only | Edit an existing Schedule (change trigger, enable/disable) | Delete a Schedule |
| SLA Configuration | Access the **⚙️Configuration \> SLA Configuration** page | Add a new SLA Configuration | Edit an existing SLA Configuration | Delete an SLA Configuration |
| Test Types | n/a | Add a new Test Type (under **Engagements \> Test Types**) | Edit an existing Test Type | n/a |
| Tool Configuration | Access the **⚙️Configuration \> Tool Configuration** page | Add a new Tool Configuration | Edit an existing Tool Configuration | Delete a Tool Configuration |
| Tool Types | Access the **⚙️Configuration \> Tool Types** page | Add a new Tool Type | Edit an existing Tool Type | Delete a Tool Type |
| Users | Access the **👤Users \> Users** page | Add a new User to DefectDojo | Edit an existing User | Delete a User |

1. Access to the Finding Templates page also requires the **Writer, Maintainer** or **Owner** Global Role for this user.

## Group Configuration Permissions

| Configuration Permission | **Reader** | **Maintainer** | **Owner** |
| --- | --- | --- | --- |
| View Group | ☑️ | ☑️ | ☑️ |
| Remove self from Group | ☑️ | ☑️ | ☑️ |
| Edit a Member’s role in a Group |  | ☑️ | ☑️ |
| Edit or Delete an Asset or Organization Membership from a Group¹ |  | ☑️ | ☑️ |
| Change a Group Member’s role to Owner |  |  | ☑️ |
| Delete Group |  |  | ☑️ |

1. This also requires the User to have at least a Maintainer Role on the Asset or Organization which they wish to edit.
