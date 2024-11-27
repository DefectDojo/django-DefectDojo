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


![image](images/Set_a_User's_Permissions.png)
​
2. Click the name of the account that you wish to give Superuser privileges to. This will bring you to their User Page.  
​
3. From the Default Information section of their User Page, open the ☰ menu and select Edit.  
​


![image](images/Set_a_User's_Permissions_2.png)
  
​
4. From the Edit User page:   
​  
For Superuser Status, check off the ☑️Superuser Status box, located in the user's Default Information.  
​  
To assign a Global Role, select one from the dropdown Global Role menu at the bottom of the page.  
​


![image](images/Set_a_User's_Permissions_3.png)
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



![image](images/Set_a_User's_Permissions_4.png)
2. Locate the **Members** heading, click the **☰** menu, and select **\+ Add Users**.
3. This will take you to a page where you can **Register new Members**. Select a User from the dropdown Users menu.
4. Select the Role that you want that User to have on this Product or Product Type: **API Importer, Reader, Writer, Maintainer** or **Owner.**  
​


![image](images/Set_a_User's_Permissions_5.png)


Users cannot be assigned as Members on a Product or Product Type without also having a Role. If you're not sure which Role you want a new user to have, **Reader** is a good 'default' option. This will keep your Product state secure until you make your final decision about their Role.



## Edit Or Delete a Member from a Product or Product Type


Members can have their Role changed within a Product or Product Type.


Within the **Product** or **Product Type** page, navigate to the **Members** heading and click the **⋮** button next to the User who you want to Edit or Delete.



![image](images/Set_a_User's_Permissions_6.png)
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


![image](images/Set_a_User's_Permissions_7.png)
  
​
2. Click the name of the account that you wish to edit.  
​
3. Navigate to the Configuration Permissions List. This is located on the right\-hand side of the User Page.  
​
4. Select the User Configuration Permissions you wish to add.  
​

For a detailed breakdown of User Configuration Permissions, please refer to our [Permission Chart](https://support.defectdojo.com/en/articles/8758189-user-access-roles-permissions-list#h_7258f7b1bd).

