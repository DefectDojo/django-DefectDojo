---
title: "Set a User's Permissions"
description: "How to grant Roles & Permissions to a user, as well as superuser status"
---

# Introduction to Permission Types


Individual users have four different kinds of permission that they can be assigned:


* Users can be assigned as **Members to Products or Product Types**. This allows them to view and interact with Data Types (Product Types, Products, Engagements, Tests and Findings) in DefectDojo depending on the role they are assigned on the specific Product. Users can have multiple Product or Product Type memberships, with different levels of access.  
​
* Users can also have **Configuration Permissions** assigned, which allow them to access configuration pages in DefectDojo. Configuration Permissions are not related to Products or Product Types.  
​
* Users can be assigned **Global Roles**, which give them a standardized level of access to all Products and Product Types.  
​
* Users can be set up as **Superusers**: administrator level roles which give them control and access to all DefectDojo data and configuration.

You can also create Groups if you want to assign Product Membership, Configuration Permissions or Global Roles to a group of users at the same time. If you have a large number of users in DefectDojo, such as a dedicated testing team for a particular Product, Groups may be a more helpful feature. 



# Superusers \& Global Roles


Part of your Role\-Based Access Control (RBAC) configuration may require you to create additional Superusers, or users with Global Roles.


* Superusers (Admins) have no limitations in the system. They can change all settings, manage users and have read / write access to all data. They can also change access rules for all users in DefectDojo. Superusers will also receive notifications for all system issues and alerts.
* Users with Global Roles can view and interact with any Data Type (Product Types, Products, Engagements, Tests and Findings) in DefectDojo depending on their assigned Role. For more information about each Role and associated privileges, please refer to our Introduction to Roles article.
* Users can also have specific Configuration Permissions assigned, allowing them to access certain DefectDojo configuration pages. Users have no Configuration Permissions by default.

By default, the first account created on a new DefectDojo instance will have Superuser permissions. That user will be able to edit permissions for all subsequent DefectDojo users. Only an existing Superuser can add another superuser, or add a Global Role to a user.



## Add Superuser or Global Role status to an existing user


1. Navigate to the 👤 Users \> Users page on the sidebar. You will see a list of all registered accounts on DefectDojo, along with each account's Active status, Global Roles, and other relevant User data.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/921088885/49c62c711a3c48cda2d0f46a/4tacIUafivFb_ju8ii4dvCF4qnCGT1ZUPLAFP2uHdkcO0nntMgLk4V2m6BO3Hd_aRjK_Ivx7HKEa_x3lFVTZJ2Sr-llUBnG4OIsJLppyFl7zzVEOFDlV69pPtNy4Qz8fslEt_ofwCWw9xeXipYcHxFQ?expires=1729720800&signature=e68d2f5001311dc6ed0709309f255315c8a98c54f7a907d6794db9069af0baae&req=fSImFsF2lYlaFb4f3HP0gBqwDj2FOqeiaXGhVvQWwTRLmeyM7l6AyrQ%2FJiOn%0AYUc%3D%0A)
​
2. Click the name of the account that you wish to give Superuser privileges to. This will bring you to their User Page.  
​
3. From the Default Information section of their User Page, open the ☰ menu and select Edit.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/921088889/3e17242c961974a7123f628a/Q8IgH7ucjqbqGd2-b94pc-zQgSVHqW2Olj7m-jENbpaOZNZrOj9WkYiptya-zeMa3u-GXtunys7BBipAIxoSHtQoVhTTAelcNIvWiYC71lZsWxThEwUFecZF3TVyy4PmluxMkSBjPiHDvT-zjvYjHsw?expires=1729720800&signature=93c6b6dc04a176f903de40fecdf2b4042ee177d8f5eb20574eef3d7432b33892&req=fSImFsF2lYlWFb4f3HP0gNz3X5m3J2OGLTvs0YS0wl7%2BnHULfElrbz%2FcFDbF%0An3E%3D%0A)
  
​
4. From the Edit User page:   
​  
For Superuser Status, check off the ☑️Superuser Status box, located in the user's Default Information.  
​  
To assign a Global Role, select one from the dropdown Global Role menu at the bottom of the page.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/921088893/dc5a8396e99a2d90e09bf5e9/Q8IgH7ucjqbqGd2-b94pc-zQgSVHqW2Olj7m-jENbpaOZNZrOj9WkYiptya-zeMa3u-GXtunys7BBipAIxoSHtQoVhTTAelcNIvWiYC71lZsWxThEwUFecZF3TVyy4PmluxMkSBjPiHDvT-zjvYjHsw?expires=1729720800&signature=22d9f11705570d018ab011b4b0cf3861e9d60e81a403f05b6c3385cddedc3df4&req=fSImFsF2lYhcFb4f3HP0gEHWxU%2Fw7IhY1p%2B8xccylok4xhfqgvF8k4tVqRb6%0AuKw%3D%0A)
​
5. Click Submit to accept these changes.  
 ​

# Product \& Product Type Membership


By default, any new account created on DefectDojo will not have permission to view any Product Level Data. They will need to be assigned membership to each Product they want to view and interact with.


* Product \& Product Type membership can only be configured by **Superusers, Maintainers or Owners**.
* **Maintainers \& Owners** can only configure membership on Products / Product Types that they are already assigned to.
* **Global Maintainers \& Owners** can configure membership on any Product or Product Type, as can **Superusers**.

Users can have two kinds of membership simultaneously at the **Product** level:


* The Role conferred by their underlying Product Type membership, if applicable
* Their Product\-specific Role, if one exists.

If a user has already been added as a Product Type member, and does not require an additional level of permissions on a specific Product, there is no need to add them as a Product Member.



## Adding a new Member to a Product or Product Type


1. Navigate to the Product or Product Type which you want to assign a user to. You can select the Product from the list under **Products \> All Products**.



![](https://downloads.intercomcdn.com/i/o/921087191/89e6c1560a6f12458bfd60ab/Untitled+drawing+%281%29.png?expires=1729720800&signature=96ecb577cdc13498af657fd587b0fa8092b851d1a4420bdb5bb92f0e1dfdba75&req=fSImFsF5nIheFb4f3HP0gH8G8wzNAN%2F5uhd6ytu1ZIqaHRpLkQ5g7uSKvc6n%0ARW4%3D%0A)
2. Locate the **Members** heading, click the **☰** menu, and select **\+ Add Users**.
3. This will take you to a page where you can **Register new Members**. Select a User from the dropdown Users menu.
4. Select the Role that you want that User to have on this Product or Product Type: **API Importer, Reader, Writer, Maintainer** or **Owner.**  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/921088898/911644c75e529f4f36408a33/3KQGHqXCpiCIntLoKJCTnJTIPDumnQ288VSGAirzzQLv0P4w4tGKzeBoupA9Y8g-e_9emazzpJ59sywnkkVpJk5DhmWHwhkQjvu76JhIw_gyvCIZBPKogIb_bI3wr-eZDApCEfvpL6UuPcO3q3sSBcQ?expires=1729720800&signature=3b6df84cb44e7e1d8b070d2e015bd374dc3bae4f56f5a56af3d283cd79ea480c&req=fSImFsF2lYhXFb4f3HP0gC3Dcl8NRYb791Gt2hJngopsfDqm3RlIMSPLOXJH%0AASg%3D%0A)


Users cannot be assigned as Members on a Product or Product Type without also having a Role. If you're not sure which Role you want a new user to have, **Reader** is a good 'default' option. This will keep your Product state secure until you make your final decision about their Role.



## Edit Or Delete a Member from a Product or Product Type


Members can have their Role changed within a Product or Product Type.


Within the **Product** or **Product Type** page, navigate to the **Members** heading and click the **⋮** button next to the User who you want to Edit or Delete.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/921088901/4d9da1df5f52f9457422f991/vz995X6_fV0KC8i0mGZm6A3YYlTXBiJquoqXf4jUZ-ric3WqFj5IC9QmWsB5vAw6CLqPz8oxuMX9KFV2wlDi0W2UvOitNl-ID4hYEA5GUWN8pslt7n0gpdrmk9-Lg7cqlTjAN15y9Vc0tfpReatFiAc?expires=1729720800&signature=5a205bf6a5b9f12ff144cde08633a1e510494d71180932b03d7d8daed770e3d8&req=fSImFsF2lIFeFb4f3HP0gLeO3ql9vXX0terru04tP2SCmsisptfRp%2BPTjgid%0Ae%2BA%3D%0A)
📝 **Edit** will take you to the **Edit Member** screen, where you can change this user's **Role** (from **API Importer, Reader, Writer, Maintainer** or **Owner** to a different choice).


🗑️ **Delete** removes a User's Membership altogether. It will not remove any contributions or changes the User has made to the Product or Product Type.


* If you can't Edit or Delete a user's Membership (the **⋮** is not visible) it's because they have this Membership conferred at a **Product Type** level.
* A user can have two levels of membership within a Product \- one assigned at the **Product Type** level and another assigned at the **Product** level.


## Adding an additional Product role to a user with a related Product Type role


If a User has a Product Type\-level Role, they will also be assigned Membership with this Role to every underlying Product within the category. However, if you want this User to have a special Role on a specific Product within that Product Type, you can give them an additional Role on the Product level.


1. From the Product page, navigate to the **Members** heading, click the **☰** menu, and select **\+ Add Users** (as if you were adding a new User to the Product).
2. Select the User's name from the drop\-down menu, and select the Product Role you want that User to be assigned.


A Product Role will supersede a user’s standard Product Type Role or Global Role. For example, if a User has a Product Type Role of **Reader**, but is also assigned as an **Owner** on a Product nested under that Product Type, they will have additional **Owner** permissions added for that Product only.



However, this does not work in reverse. If a User has a Product Type Role or Global Role of **Owner**, assigning them a **Reader** role on a particular Product will not take away their **Owner** permissions. **Roles cannot take away permissions granted to a User by other Roles, they can only add additional permissions.**



# Configuration Permissions


Many configuration dialogues and API endpoints can be enabled for users or groups of users, regardless of their superuser status. These Configuration Permissions allow regular users to access and contribute to parts of DefectDojo outside of their standard Product or Product Role assignment.



Configuration Permissions are not related to a specific Product or Product Type \- users can have configuration permissions assigned without the need for other statuses or Product / Product Type Membership.  
​


## List of Configuration Permissions


* **Credential Manager:** Access to the ⚙️Configuration \> Credential Manager page
* **Development Environments:** Manage the Engagements \> Environments list
* **Finding Templates:** Access to the Findings \> Finding Templates page
* **Groups**: Access the 👤Users \> Groups page
* **Jira Instances:** Access the ⚙️Configuration \> JIRA page
* **Language Types**:Access the [Language Types](https://documentation.defectdojo.com/integrations/languages/) API endpoint
* **Login Banner**: Edit the ⚙️Configuration \> Login Banner page
* **Announcements**: Access ⚙️Configuration \> Announcements
* **Note Types:** Access the ⚙️Configuration \> Note Types page
* **Product Types:** n/a
* **Questionnaires**: Access the Questionnaires \> All Questionnaires page
* **Questions**: Access the Questionnaires \> Questions page
* **Regulations**: Access the ⚙️Configuration \> Regulations page
* **SLA Configuration:** Access the ⚙️Configuration \> SLA Configuration page
* **Test Types:** Add or edit a Test Type (under Engagements \> Test Types)
* **Tool Configuration:** Access the **⚙️Configuration \> Tool Types** page
* **Tool Types:** Access the ⚙️Configuration \> Tool Types page
* **Users:** Access the 👤Users \> Users page


## Add Configuration Permissions to a User


**Only Superusers can add Configuration Permissions to a User**.


1. Navigate to the 👤 Users \> Users page on the sidebar. You will see a list of all registered accounts on DefectDojo, along with each account's Active status, Global Roles, and other relevant User data.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/921088906/449d16d74c2ddbf786af42c3/4tacIUafivFb_ju8ii4dvCF4qnCGT1ZUPLAFP2uHdkcO0nntMgLk4V2m6BO3Hd_aRjK_Ivx7HKEa_x3lFVTZJ2Sr-llUBnG4OIsJLppyFl7zzVEOFDlV69pPtNy4Qz8fslEt_ofwCWw9xeXipYcHxFQ?expires=1729720800&signature=f40bb9c5be475ca93773f4e967a62929ba8d6c1e74998ae4f3cf2b2ce60b9dfd&req=fSImFsF2lIFZFb4f3HP0gC9vVNNi8Mjqu8Pj33LrnUR7spDzj5S4DmrcT56Z%0A244%3D%0A)
  
​
2. Click the name of the account that you wish to edit.  
​
3. Navigate to the Configuration Permissions List. This is located on the right\-hand side of the User Page.  
​
4. Select the User Configuration Permissions you wish to add.  
​

For a detailed breakdown of User Configuration Permissions, please refer to our [Permission Chart](https://support.defectdojo.com/en/articles/8758189-user-access-roles-permissions-list#h_7258f7b1bd).

