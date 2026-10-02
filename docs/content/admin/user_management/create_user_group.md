---
title: "Share permissions: User Groups"
description: "Share and maintain permissions for many users in DefectDojo Pro"
weight: 3
audience: pro
aliases:
  - /en/customize_dojo/user_management/create_user_group
---

> **DefectDojo Pro feature.** User Groups and the underlying RBAC system are part of DefectDojo Pro. Open-source DefectDojo uses the [Authorized Users](../os__authorized_users/) model — see that page for open-source access control, and the [3.0 upgrade notes](/releases/os_upgrading/3.0/#authorized-users-panel-replaces-membersgroups-under-legacy-authorization) if you're moving between editions.

If you have a significant number of DefectDojo users, you may want to create one or more **Groups**, in order to set the same Role\-Based Access Control (RBAC) rules for many users simultaneously. Only Superusers can create User Groups.

Groups can work in multiple ways:

* Set one, or many different Asset or Organization level Roles for all Group Members, allowing specific control over which Assets or Organizations can be accessed and edited by the Group.
* Set a Global Role for all Group Members, giving them visibility and access to all Asset or Organizations.
* Set Configuration Permissions for a Group, allowing them to change specific functionality around DefectDojo.

For more information on Roles, please refer to our **Introduction To Roles** article.

## The All Groups page

From the sidebar, navigate to **Settings > Users & Permissions > Groups** to see a list of all active and inactive user groups. From here, you can create, delete or view your individual Group pages.

* You can filter this table by Group Name, Description, Email Address, Global Role, as well as the total number of Users, Organizations, and Assets associated with the Group.
* You can also adjust a Group's Permissions or other settings by clicking the "⋮" button next to the Group you wish to edit.

![image](images/all_groups_pro.png)

## Viewing A Group

Viewing a group displays all Group information, such as ID, name, description, global role, etc. The Group Members, Organizations, and Assets associated with the group are also displayed. Additionally, configuration permissions tied to a Group can be updated directly from the “View Group” page.

![image](images/group_view_pro_ui.png)

* All configuration permissions are displayed in a dropdown which is grouped into subcategories. If the selection of configuration permissions is different from their current value, an “Update Configuration Permissions” button is displayed.

![image](images/groups_pro_configuration_permissions.png)

* Once a few additional permissions have been selected, the user will be asked to confirm they would like to update the permissions for the selected group before an update is made.

## Create a User Group

1. Navigate to **Settings > Users & Permissions > Groups** on the sidebar.

2. Click **\+ New Group** above the table of existing Groups.

3. In the **New Group** window, set the Name for this Group, and add a Description if you wish.

   You can also select a Global Role that you wish to apply to this Group. Adding a Global Role to the Group will give all Group Members access to all DefectDojo data, along with a limited amount of edit access depending on the Global Role you choose. See our **Introduction To Roles** article for more information.

4. Click **Submit**.

![image](images/group_pro_new_group.png)

The account that initially creates a Group will have an Owner Role for the Group by Default.

To change a Group's Name, Description, email address or Global Role later, open the Group page, click the ⚙️ button in the top right corner, and select **Edit Group**.

### Set an email address to receive reports

The Weekly Digest is a report on all Group-assigned Assets / Organizations. To have a weekly Digest sent out, enter the destination email address you wish to use in the **Email Address** field when you create or edit the Group.  Group members will still receive notifications as usual.

## Manage a Group's Users

Group Membership is managed from the individual Group page, which you can select from the list in the **Settings > Users & Permissions > Groups** page. Click the highlighted Group Name to access the Group page that you wish to edit.

In order to view or edit a Group's Membership, a User must have the appropriate Configuration permissions enabled as well as Membership in the Group (or Superuser status).

Membership is managed from the Group's **Permissions** window:

1. On the Group page, click the ⚙️ button in the top right corner and select **Permissions**. This entry is hidden from Users who cannot add or remove Group Members.

![image](images/group_pro_gear_menu.png)

2. The **Permissions for Group** window lists every current Member, along with the Role each one has in the Group.

![image](images/group_pro_permissions_dialog.png)

### Add a User to a Group

User Groups can have as many Users assigned as you wish. All Users in a Group will be given the associated Role on each Asset or Organization listed, but Users may also have Individual Roles which supersede the Group role.

Users are added to a Group **one at a time**. To add several Users, repeat the steps below for each of them.

1. In the **Permissions for Group** window, open the **Select a User** drop\-down. Type in the search box to narrow the list, then choose the User you want to add.

![image](images/group_pro_select_user.png)

2. Open the **Select a Role** drop\-down and choose the Group Role to assign to this User. This determines their ability to configure the Group.

3. Click **Add User**. The User appears in the Members table straight away, and the form is cleared so you can add the next one.

![image](images/group_pro_add_user.png)

Note that adding a member to a Group will not allow them access to their own Group page by default. This is a separate Configuration permission which must be enabled first.

If you need to add a large number of Users, you can also create Group Members through the API. Send one `POST` request per User to the `dojo_group_members` endpoint, with the `group`, `user` and `role` of the new Member. The `role` is the numeric ID of the Role, which you can look up on the `roles` endpoint.

### Edit or Remove a Member from a User Group

In the **Members** table of the **Permissions for Group** window:

* **Change a Role:** click the Role shown next to the User's name and select a different Role from the menu (for example, from Reader to Maintainer or Owner). The change is saved as soon as you pick the new Role.
* **Remove a Member:** click the 🗑️ button at the end of the User's row. This removes a User's Membership altogether, and takes effect immediately, without a confirmation prompt. It will not remove any contributions or changes the User has made to the Asset or Organization.

## Manage a Group's Permissions

Note that only Superusers can edit a Group's permissions (Asset / Organization, or Configuration).

### Add Asset Roles or Organization Roles for a Group

You can register a Group on as many Assets or Organizations as you wish, with a different Role on each. A Group is added to an Asset or Organization from that Asset or Organization, rather than from the Group page. The Group page lists the result, under the Organizations and Assets the Group can access.

1. Open the Asset or Organization you want the Group to have access to, click the ⚙️ button in the top right corner, and select **Permissions**.

2. In the **Permissions** window, select the **Groups** tab at the top. The **Users** tab beside it is where individual Users are given a Role on the same Asset or Organization.

3. Open the **Select a Group** drop\-down and choose the Group.

4. Open the **Select a Role** drop\-down and choose the Role that you want all Group members to have regarding this particular Asset or Organization.

5. Click **Add Group**.

![image](images/group_pro_asset_groups.png)

Groups cannot be assigned to Assets or Organizations without a Role. If you're not sure which Role you want a Group to have, Reader is a good 'default' option. This will keep your Asset state secure until you make your final decision about the Group Role.

As with Group Members, a Group's Role on an Asset or Organization can be changed from the Role shown in its row, and the Group can be removed with the 🗑️ button.

> Depending on your instance's settings, Assets and Organizations may be labelled **Products** and **Product Types** in the interface. They are the same objects.

### Assign Configuration Permissions to a Group

If you want the Members in your Group to access Configuration functions, and control certain aspects of DefectDojo, you can assign these responsibilities from the Group page, using the **Configuration Permissions** drop\-down described in [Viewing A Group](#viewing-a-group).

Select the permissions you want from the drop\-down, click **Update Configuration Permissions**, and confirm the change.
