---
title: "User permissions & Roles"
description: "Summary of all DefectDojo permission options, in detail"
weight: 1
---

If you have a team of users working in DefectDojo, it's important to set up Role\-Based Access Control (RBAC) appropriately so that users can only access specific data. Security data is highly sensitive, and DefectDojo's options for access control allow you to be specific about each team member’s access to information.

## Types of Permissions

DefectDojo manages four different kinds of permissions:

* Users can be assigned as **Members** to **Products or Product Types**. A Product Membership comes with a **Role** which allows your users to view and interact with Data Types (Product Types, Products, Engagements, Tests and Findings) in DefectDojo. Users can have multiple Product or Product Type memberships, with different levels of access.   
​
* Users can also have **Configuration Permissions** assigned, which allow them to access configuration pages in DefectDojo. Configuration Permissions are not related to Products or Product Types, and are not associated with Roles.  
​
* Users can be assigned **Global Roles**, which give them a standardized level of access to all Products and Product Types.  
​
* Users can be set up as **Superusers**: administrator level roles which give them control and access to all DefectDojo data and configuration.

Each of these Permission types can also be assigned to **User** **Group**. If you have a large number of users in DefectDojo, such as a dedicated testing team for a particular Product, Groups allow you to set up and maintain permissions quickly.

## Product/Product Type Membership \& Roles

When users are assigned as members to a Product or Product Type, they also receive a role which controls how they interact with the associated Finding data.

### Role Summaries

Users can be assigned a role of Reader, Writer, Maintainer, Owner or API Importer, either globally or within a Product / Product Type.

‘Underlying data’ refers to all Products, Engagements, Tests, Findings or Endpoints nested under a Product, or Product Type.

* **Reader Users** can view underlying data on any Product or Product Type they are assigned to, and add comments. They cannot edit, add or otherwise modify any of the underlying data, but they can export Reports and add Notes to data.  
​
* **Writer Users** have all Reader abilities, plus the ability to Add or Edit Engagements, Tests and Findings. They cannot add new Products, and they cannot Delete any underlying data.  
​
* **Maintainer Users** have all Writer abilities, plus the ability to edit Product or Product Types. They can add new Members with Roles to the Product or Product Type, and they can also Delete Engagements, Tests, and Findings.  
​
* **Owner Users** have the greatest amount of control over a Product or Product Type. They can designate other Owners, and can also Delete the Products or Product Types they’re assigned to.  
​
* **API Importer** **Users** have limited abilities. This Role allows limited API access without exposing the majority of the API endpoints, so is useful for automation or users who are meant to be ‘external’ to DefectDojo. They can view underlying data, Add / Edit Engagements, and Import Scan Data.

For detailed information on Roles, please see our **[Role Permission Chart](../user-permission-charts/)**.

### Global Roles

Users with **Global Roles** can view and interact with any Data Type (Product Types, Products, Engagements, Tests and Findings) in DefectDojo depending on their assigned Role.

### Group Memberships

User Groups can be added as Members of a Product or Product Type. Users who are part of the Group will inherit access to all associated Products or Product Types, and will inherit the Role assigned to the Group.

#### Users with multiple roles

* If a User is assigned as a member of a Product, they are not granted any associated Product Type permissions by default.

* A User's Product Role always supersedes their 'default' Product Type Role.  
​
* A User's Product / Product Type Role always supersedes their Global Role within the underlying Product or Product Type. For example, if a User has a Product Type Role of Reader, but is also assigned as an Owner on a Product nested under that Product Type, they will have additional Owner permissions added for that Product only.   
​
* Roles cannot take away permissions, they can only add additional ones. For example, If a User has a Product Type Role or Global Role of Owner, assigning them a Reader role on a particular Product will not take away their Owner permissions on that Product.  
​
* Superuser status always supersedes any Roles assigned.

## Superusers

Superusers (Admins) have no limitations in the system. They can change all settings, manage users and have read / write access to all data. They can also change access rules for all users in DefectDojo. Superusers will also receive notifications for all system issues and alerts.

By default, the first account created on a new DefectDojo instance will have Superuser permissions. That user will be able to edit permissions for all subsequent DefectDojo users. Only an existing Superuser can add another superuser, or add a Global Role to a user. 

## Configuration Permissions

Configuration Permissions, although similar, are not related to Products or Roles. They must be assigned separately from Roles. **Regular** **users do not have any Configuration Permissions by default, and assigning these configuration permissions should be done carefully.**

Users can have Configuration Permissions assigned in different ways:

1. Users can be assigned Configuration Permissions directly. Specific permissions can be configured directly on a User page.  

2. User Groups can be assigned Configuration Permissions. As with Roles, specific Configuration Permissions can be added to Groups, which will give all Group members these permissions.

Superusers have all Configuration Permissions, so they do not have a Configuration Permission section on their User page.

### Group Configuration Permissions

If users are part of a Group, they also have Group Configuration Permissions which control their level of access to a Group’s configuration. Group Permissions do not correspond to the Group’s Product or Product Type membership.

If users create a new Group, they will be given the Owner role of the new Group by default.

For more information on Configuration Permissions, see our **[Configuration Permissions Chart](../user_permission_chart/#configuration-permission-chart)**.
