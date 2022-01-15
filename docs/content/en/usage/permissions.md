---
title: "Permissions"
description: "Users have different functionality available to them, depending on their system-wide permissions and on the role they have as a member of a particular Product or Product Type."
weight: 3
draft: false
---

## System-wide permissions

* Administrators (aka superusers) have no limitations in the system. They can change all settings, manage users  and have read and write access to all data.
* Staff users can add Product Types, and have access to data according to their role in a Product or Product Type.
* Regular users have limited functionality available. They cannot add Product Types but have access to data according to their role in a Product or Product Type

## Product and Product Type permissions

Users can be assigned as members to Products and Product Types, giving them one out of five predefined roles. The role defines what kind of access a user has to functions for interacting with data of that Product or Product Type:

**Product / Product Type roles:**

|                             | Reader | Writer | Maintainer | Owner | API Importer |
|-----------------------------|:------:|:------:|:----------:|:-----:|:------------:|
| Add Product Type            |        |        | <sup>1)</sup>           |<sup>1)</sup>       |              |
| View Product Type           | x      | x      | x          | x     | x            |
| Remove yourself as a member | x      | x      | x          | x     |              |
| Manage Product Type members |        |        | x          | x     |              |
| Edit Product Type           |        |        | x          | x     |              |
| Add Product                 |        |        | x          | x     |              |
| Add Product Type member as Owner |   |        |            | x     |              |
| Delete Product Type         |        |        |            | x     |              |
|                             |        |        |            |       |              |
| View Product                | x      | x      | x          | x     |  x           |
| Remove yourself as a member | x      | x      | x          | x     |              |
| Manage Product members      |        |        | x          | x     |              |
| Edit Product                |        |        | x          | x     |              |
| Add Product member as Owner |        |        |            | x     |              |
| Delete Product              |        |        |            | x     |              |
|                             |        |        |            |       |              |
| View Engagement             | x      | x      | x          | x     |  x           |
| Add Engagement              |        | x      | x          | x     |              |
| Edit Engagement             |        | x      | x          | x     |              |
| Risk Acceptance             |        | x      | x          | x     |              |
| Delete Engagement           |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Test                   | x      | x      | x          | x     | x            |
| Add Test                    |        | x      | x          | x     |              |
| Edit Test                   |        | x      | x          | x     |              |
| Delete Test                 |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Finding                | x      | x      | x          | x     | x            |
| Add Finding                 |        | x      | x          | x     |              |
| Edit Finding                |        | x      | x          | x     |              |
| (Re-)Import Scan Result     |        | x      | x          | x     | x            |
| Delete Finding              |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Finding Group          | x      | x      | x          | x     | x            |
| Add Finding Group           |        | x      | x          | x     |              |
| Edit Finding Group          |        | x      | x          | x     |              |
| Delete Finding Group        |        | x      | x          | x     |              |
|                             |        |        |            |       |              |
| View Endpoint               | x      | x      | x          | x     | x            |
| Add Endpoint                |        | x      | x          | x     |              |
| Edit Endpoint               |        | x      | x          | x     |              |
| Delete Endpoint             |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| Edit Benchmark              |        | x      | x          | x     |              |
| Delete Benchmark            |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Components             | x      | x      | x          | x     | x            |
|                             |        |        |            |       |              |
| View Note History           | x      | x      | x          | x     |              |
| Add Note                    | x      | x      | x          | x     |              |
| Edit Note                   | (x) <sup>2)</sub> | x                 | x          | x     |              |
| Delete Note                 | (x) <sup>2)</sub> | (x) <sup>2)</sub> | x          | x     |              |


<sup>1)</sup> Every staff user and administrator can add Product Types. Regular users are not allowed to add Product Types, unless they are Global Owner or Maintainer.

<sup>2)</sup> Every user is allowed to edit and delete his own notes.

The role of a user within a Product Type is inherited by all Products of that Product Type, unless the user is explicitly defined as a member of a Product with a different role. In that case, if a user doesn't have a certain right for the Product Type, it is then checked if he has the right for the Product.

A Product Type needs to have at least one owner. The last owner cannot be removed.

## Global permissions

Users can be assigned a global role in the *Edit User* dialog. A global role gives a user access to all Product Types and Products, including the underlying data, with permissions according to the respective role.

A use case for a global role could be the Chief Information Security Officer of a company who needs an overview of all systems. If he gets the global role `Reader`, he can see the findings for all products and also all metrics.

Since global roles give users access to all data, only superusers are allowed to edit it.

## Groups ##

If you have a number of users who should all have the same permissions for some Products or Product Types, you can put them together in a group. The group defines the roles for Products and Product Types that are applied to all members of the group.

The membership of a group itself has a role that determines what permissions the member has to manage the group:

|                             | Reader | Maintainer | Owner |
|-----------------------------|:------:|:----------:|:-----:|
| Add Group <sup>1)</sup>     |        |            |       |
| View Group                  | x      | x          | x     |
| Remove yourself as a member | x      | x          | x     |
| Manage Group members        |        | x          | x     |
| Edit Group                  |        | x          | x     |
| Add Group member as Owner   |        |            | x     |
| Delete Group                |        |            | x     |

<sup>1)</sup> Every staff user and administrator can add groups. Regular users are not allowed to add groups.

The permissions to manage the roles of Products and Product types for a group is defined by the role of the user in the respective Product or Product Type.

Groups can have a global role too. This global role gives all members of the group access to all Product Types and Products, including the underlying data, with permissions according to the respective role.

## Configuration permissions

Release 2.7.0 contains a beta functionality to make permissions for the configuration of DefectDojo more flexible. When the settings parameter `FEATURE_CONFIGURATION_AUTHORIZATION` is set to `True`, many configuration dialogues and API endpoints can be enabled for users or groups of users, regardless of their **Superuser** or **Staff** status:

![Configuration permissions](../../images/configuration_permissions.png)

3 configurations can still only be changed by superusers:
* System settings
* Notifications on system level
* Configuration permissions for users and groups

{{% alert title="Warning" color="warning" %}}
These configuration settings are a powerful tool and should be used with great care.
{{% /alert %}}
