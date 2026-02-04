---
title: "Share permissions: User Groups"
description: "Share and maintain permissions for many users"
weight: 3
---

If you have a significant number of DefectDojo users, you may want to create one or more **Groups**, in order to set the same Role\-Based Access Control (RBAC) rules for many users simultaneously. Only Superusers can create User Groups.

Groups can work in multiple ways:

* Set one, or many different Product or Product Type level Roles for all Group Members, allowing specific control over which Products or Product Types can be accessed and edited by the Group.
* Set a Global Role for all Group Members, giving them visibility and access to all Product or Product Types.
* Set Configuration Permissions for a Group, allowing them to change specific functionality around DefectDojo.

For more information on Roles, please refer to our **Introduction To Roles** article.

## The All Groups page

From the sidebar, navigate to 👤**Users \> Groups** to see a list of all active and inactive user groups. 

![image](images/Create_a_User_Group_for_shared_permissions.png)
From here, you can create, delete or view your individual Group pages.

For <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users, the Pro UI's All Groups has a few additional options.
* You can filter this table by Group Name, Description, E-mail Address, Global Role, as well as the total number of Users, Product Types, and Products associated with the Group.
* You can also adjust a Group's Permissions or other settings by clicking the "⋮" button next to the Group you wish to edit.

![image](images/all_groups_pro.png)

## Viewing A Group

Viewing a group displays all Group information, such as ID, name, description, global role, etc. The Group Members, Product Types, and Products associated with the group are also displayed. Additionally, configuration permissions tied to a Group can be updated directly from the “View Group” page.

For <span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Pro</span> users, the Pro UI's Group View allows you to assign Configuration Permission adjustments in a slightly different way.

![image](images/group_view_pro_ui.png)

* All configuration permissions are displayed in a dropdown which is grouped into subcategories. If the selection of configuration permissions is different from their current value, an “Update Configuration Permissions” button is displayed.

![image](images/groups_pro_configuration_permissions.png)

* Once a few additional permissions have been selected, the user will be asked to confirm they would like to update the permissions for the selected group before an update is made.

## Create / Edit a User Group

1. Navigate to the 👤**Users \> Groups** page on the sidebar. You will see a list of all existing User Groups, including their Name, Description, Number of Users, Global Role (if applicable) and Email.  
​
![image](images/Create_a_User_Group_for_shared_permissions_2.png)

2. Click the **🛠️ button** next to the All Groups heading, and select **\+ New Group.**   
​
![image](images/Create_a_User_Group_for_shared_permissions_3.png)
  

3. This will take you to a page where you can create a new Group. Set the Name for this Group, and add a Description if you wish.  
  
You can also select a Global Role that you wish to apply to this Group, if you wish. Adding a Global Role to the Group will give all Group Members access to all DefectDojo data, along with a limited amount of edit access depending on the Global Role you choose. See our **Introduction To Roles** article for more information.

The account that initially creates a Group will have an Owner Role for the Group by Default.

### Set an email address to receive reports

The Weekly Digest is a report on all Group-assigned Products / Product Types. To have a weekly Digest sent out, enter the destination email address you wish to use on the Create / Edit Group form.  Group members will still receive notifications as usual.

### Viewing a Group Page

Once you have created a Group, you can access it by selecting it in the menu listed under **Users \> Groups.**

The Group Page can be customized with a **Description**.It features a list of all **Group Members,** as well as the assigned **Products, Product Types**, and the associated **Role** associated with each of these**.**

You can also see the Group’s **Configuration Permissions** listed here.

## Manage a Group’s Users

Group Membership is managed from the individual Group page, which you can select from the list in the **Users \> Groups** page. Click the highlighted Group Name to access the Group page that you wish to edit.

In order to view or edit a Group’s Membership, a User must have the appropriate Configuration permissions enabled as well as Membership in the Group (or Superuser status).

### **Add a User to a Group**

User Groups can have as many Users assigned as you wish. All Users in a Group will be given the associated Role on each Product or Product Type listed, but Users may also have Individual Roles which supersede the Group role.

1. From the Group page, select **\+ Add Users** from the **☰** button at the edge of the **Members** heading.  
​
![image](images/Create_a_User_Group_for_shared_permissions_4.png)

2. This will take you to the **Add Some Group Members** screen. Open the Users drop\-down menu, and then check off each user that you wish to add to the Group.  
​
![image](images/Create_a_User_Group_for_shared_permissions_5.png)

3. .Select the Group Role that you wish to assign these Users. This determines their ability to configure the Group.

Note that adding a member to a Group will not allow them access to their own Group page by default. This is a separate Configuration permission which must be enabled first.

### **Edit or Delete a Member from a User Group**

1. From the Group page, select the ⋮ next to the Name of the User you wish to Edit or Delete from the Group.  

**📝 Edit** will take you to the Edit Member screen, where you can change this user's Role (from Reader, Maintainer or Owner to a different choice).  

**🗑️ Delete** removes a User's Membership altogether. It will not remove any contributions or changes the User has made to the Product or Product Type.

![image](images/Create_a_User_Group_for_shared_permissions_6.png) 

## Manage a Group’s Permissions

Group Permissions are managed from the individual Group page, which you can select from the list in the **Users \> Groups** page. Click the highlighted Group Name to access the Group page that you wish to edit.

Note that only Superusers can edit a Group’s permissions (Product / Product Type, or Configuration).  
​
### **Add Product Roles or Product Type Roles for a Group**

You can register as many Product Roles or Product Type Roles as you wish in each Group.

1. From the Group page, select **\+ Add Product Types**, or \+ **Add Product** from the relevant heading (Product Type Groups or Product Groups).  
​
![image](images/Create_a_User_Group_for_shared_permissions_7.png)

2. This will take you to a **Register New Products / Product Types** Page, where you can select a Product or Product Type to add from the drop\-down menu.

![image](images/Create_a_User_Group_for_shared_permissions_8.png)

3. Select the Role that you want all Group members to have regarding this particular Product or Product Type.

Groups cannot be assigned to Products or Product Types without a Role. If you're not sure which Role you want a Group to have, Reader is a good 'default' option. This will keep your Product state secure until you make your final decision about the Group Role.

### **Assign Configuration Permissions to a Group**

If you want the Members in your Group to access Configuration functions, and control certain aspects of DefectDojo, you can assign these responsibilities from the Group page. 

Assign View, Add, Edit or Delete roles from the menu in the bottom\-right hand corner. Checking off a Configuration Permission will immediately give the Group access to this particular function.

![image](images/Create_a_User_Group_for_shared_permissions_9.png)
