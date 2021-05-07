---
title: "Permissions"
description: "Users have different functionality available to them, depending on their system-wide permissions and on the role they have as a member of a particular Product or Product Type."
weight: 3
draft: false
---

{{% alert title="Warning" color="warning" %}}
The permissions described on this page only become active if you set the ``FEATURE_AUTHORIZATION_V2`` feature flag to ``True``. This feature is currently in beta, you should not use it in production environments.
{{% /alert %}}

## System-wide permissions

* Administrators (aka super users) have no limitations in the system. They can change all settings, manage users  and have read and write access to all data.
* Staff users can add Product Types, and have access to data according to their role in a Product or Product Type. There is the parameter `AUTHORIZATION_STAFF_OVERRIDE` in the settings to give staff users full access to all Products and Product Types.
* Guest users have limited functionality available. They cannot add Product Types but have access to data according to their role in a Product or Product Type

## Product and Product Type permissions

Users can be assigned as members to Products and Product Types, giving them one out of five predefined roles. The roles define what kind of access a user has to functions for interacting with data of that Product or Product Type:

**Product / Product Type roles:**

|                             | Reader | Writer | Maintainer | Owner | API Importer |
|-----------------------------|:------:|:------:|:----------:|:-----:|:------------:|
| Add Product Type <sup>1)</sup> |     |        |            |       |              |
| View Product Type           | x      | x      | x          | x     |              |
| Remove yourself as a member | x      | x      | x          | x     |              |
| Manage Product Type members |        |        | x          | x     |              |
| Edit Product Type           |        |        | x          | x     |              |
| Add Product                 |        |        | x          | x     |              |
| Add Product Type member as Owner |   |        |            | x     |              |
| Delete Product Type         |        |        |            | x     |              |
|                             |        |        |            |       |              |
| View Product                | x      | x      | x          | x     |              |
| Remove yourself as a member | x      | x      | x          | x     |              |
| Manage Product members      |        |        | x          | x     |              |
| Edit Product                |        |        | x          | x     |              |
| Add Product member as Owner |        |        |            | x     |              |
| Delete Product              |        |        |            | x     |              |
|                             |        |        |            |       |              |
| View Engagement             | x      | x      | x          | x     |              |
| Add Engagement              |        | x      | x          | x     |              |
| Edit Engagement             |        | x      | x          | x     |              |
| Risk Acceptance             |        | x      | x          | x     |              |
| Delete Engagement           |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Test                   | x      | x      | x          | x     |              |
| Add Test                    |        | x      | x          | x     |              |
| Edit Test                   |        | x      | x          | x     |              |
| Delete Test                 |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Finding                | x      | x      | x          | x     |              |
| Add Finding                 |        | x      | x          | x     |              |
| Edit Finding                |        | x      | x          | x     |              |
| (Re-)Import Scan Result     |        | x      | x          | x     | x            |
| Delete Finding              |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Finding Group          | x      | x      | x          | x     |              |
| Add Finding Group           |        | x      | x          | x     |              |
| Edit Finding Group          |        | x      | x          | x     |              |
| Delete Finding Group        |        | x      | x          | x     |              |
|                             |        |        |            |       |              |
| View Endpoint               | x      | x      | x          | x     |              |
| Add Endpoint                |        | x      | x          | x     |              |
| Edit Endpoint               |        | x      | x          | x     |              |
| Delete Endpoint             |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| Edit Benchmark              |        | x      | x          | x     |              |
| Delete Benchmark            |        |        | x          | x     |              |
|                             |        |        |            |       |              |
| View Components             | x      | x      | x          | x     |              |
|                             |        |        |            |       |              |
| View Note History           | x      | x      | x          | x     |              |
| Add Note                    |        | x      | x          | x     |              |
| Edit Note                   |        | x      | x          | x     |              |
| Delete Note                 |        | (x) <sup>2)</sub> | x          | x     |              |


<sup>1)</sup> Every staff user and administrator can add Product Types. Guest users are not allowed to add Product Types.

<sup>2)</sup> Every user is allowed to delete his own notes.

The role of a user within a Product Type is inherited by all Products of that Product Type, unless the user is explicitly defined as a member of a Product with a different role. In that case, if a user doesn't have a certain right for the Product Type, it is then checked if he has the right for the Product.

A Product Type needs to have at least one owner. The last owner cannot be removed.
