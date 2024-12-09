---
title: "How-To: Add, Edit or Delete Dashboard Tiles"
description: "Set up custom filters to track your work"
---

Custom Dashboard Tiles can be added, edited or deleted by any user with **Superuser** Permissions.

## Adding a new Dashboard Tile

New Dashboard tiles can be added by opening the **\+** (plus icon)menu on the Dashboard. New Dashboard tiles will always be created at the bottom of the Dashboard Tiles section.

![image](images/How-To_Add,_Edit_or_Delete_Dashboard_Tiles.png)

Select the kind of Tile you want to add, which will then bring you to the Add Dashboard Tile form.

### Editing a Dashboard Tile

If you wish to edit a Dashboard Tile, you can click the Header of the Tile, which will also open the Dashboard Tile form.

## Add / Edit Dashboard Tile form

From here you can set your Dashboard Tile’s options:

![image](images/How-To_Add,_Edit_or_Delete_Dashboard_Tiles_2.png)

* Set the **Header** textfor your tile **(3\)**
* Set the **Footer** textfor your tile
* Set the **Color** of your icon

![image](images/How-To_Add,_Edit_or_Delete_Dashboard_Tiles_3.png)

## Dynamic Color Tile

If you want to set your tile to change color based on the associated count of Findings, Products or other objects returned by the filter, you can enable **Dynamic Color Tile** in this menu. The color of the tile Icon will change from Green \-\> Yellow \-\> Red as the object count changes.

* **Dynamic Color Minimum is the bottom of the range. If the Object count is equal to or less than this number, the tile Icon will be set to Green.**
* **Dynamic Color Maximum** is the top of the range. If the Object count is equal to or greater than this number, the tile Icon will be set to Red.
* Any number between the Minimum or the Maximum will set the filter to Yellow.

### **Example 1: Critical Findings Count**

Say you wanted to set up a Dynamic Color Tile to track our Critical Findings. You can set your Dynamic Color parameters as follows:

* Set **Dynamic Color Minimum** to 0\. As long as you have 0 active Critical Findings, this tile will be **Green**.
* Set **Dynamic Color Maximum** to 5\. If you have 5 or more Critical Findings active in our environment, the tile will turn **Red** to indicate there’s timely action required to address these Findings.
* If you have 1\-4 Critical Findings in your instance, the filter will be **Yellow** to indicate that we’re not in an ‘emergency’ situation but we should be aware of these Findings.

Of course, your team’s standards and acceptable range for this kind of filter may differ from our example.

## Inverted Maximum and Minimum

If your Maximum is lower than your Minimum, the range will still compute correctly.

**Example 2: Passing Products Count**

Say you wanted to set up a Tile which tracks your Passing Products with a Dynamic Color. An acceptable count of Passing Products for you is 5 or more, and a ‘failing’ state is 2 or fewer Passing Products.

You can set your **Dynamic Color Maximum** of 2, and a **Dynamic Color Minimum** of 5, the Tile will apply colors as follows:

* If the filter returns 2 Objects or fewer , the tile will be **Red**, indicating that very few of your Products are passing.
* If the filter returns 5 Objects or greater, the tile will be **Green**, indicating that a healthy amount of your Products are passing.
* If the filter returns a value between those two numbers, the tile will be **Yellow**, indicating that a significant, but non\-critical amount of your Products are not passing.

## Tile Filter Index

To set a specific context for your tile, you can set various Tile Filters. Click the **Tile Filters \+** button at the bottom of the form to expand the Tile Filters menu.

Filters are optional. Each Tile has a different set of relevant filters which can be selected.

### Product Tile

* **Product Name Contains**: type in one or more partial matches of Product Names, separated by commas
* **Product Name Exact**: type in one or more exact matches of Product Names, separated by commas
* **Product Type:** Select one or more options from the list
* **Business Criticality**: Select one or more options from the list
* **Platform**: Select one or more options from the list
* **Lifecycle:** Select one or more options from the list
* **Origin:** Select one or more options from the list
* **External Audience:** Yes/No
* **Internet Accessible:** Yes/No
* **Has Tags**: Yes/No
* **Tags:** type in one or more exact matches of tags, separated by commas
* **Tag Contains:** type in one or more partial matches of tags, separated by commas
* **Outside of SLA**: Yes/No

### Engagement Tile

* **Product Name Contains**: type in one or more partial matches of Product Names, separated by commas
* **Product Type**: Select one or more options from the list
* **Engagement Name Contains**: type in one or more partial matches of Engagements, separated by commas
* **Engagement Lead**: Select a single option from the list
* **Engagement Version**: type in an Engagement Version
* **Test Version**: type in a Test Version
* **Product Lifecycle**: Select one or more options from the list
* **Engagement Status**: Select one or more options from the list
* **Has Tags**: Yes/No
* **Tags:** type in one or more exact matches of tags, separated by commas
* **Tag Contains:** type in one or more partial matches of tags, separated by commas
* **Does Not Have Tags**: type in one or more exact matches tags to ignore, separated by commas
* **Tag Does Not Contain**: type in one or more partial matches of tags to ignore, separated by commas

### Test Tile

* **Test Name Contains**: type in one or more partial matches of Test Names, separated by commas
* **Test Type**: select a single Test Type from the list
* **Engagement**: select a single Engagement from the list
* **Test Version:** type in a Test Version
* **Branch/Tag**: type in a Branch/Tag
* **Build ID**: type in a Build ID
* **Commit Hash**: type in a Commit Hash
* **Engagement Tag Contains: type in one or more partial matches of tags, separated by commas**
* **Engagement Tag Does Not Contain**: type in one or more partial matches of tags to ignore, separated by commas
* **Product Tag Contains**: type in one or more partial matches of tags, separated by commas
* **Product Tag Does Not Contain**: type in one or more partial matches of tags to ignore, separated by commas
* **Has Tags**: Yes/No
* **Tags**: type in one or more exact matches of tags, separated by commas
* **Tag Contains**: type in one or more partial matches of tags, separated by commas
* **Does Not Have Tags**: type in one or more exact matches tags to ignore, separated by commas
* **Tag Does Not Contain**: type in one or more partial matches of tags to ignore, separated by commas

### Finding Tile

* **Name Contains**: enter a partial match of a Finding Name from the menu
* **Component Name Contains**: enter a partial match of a Component Name from the menu
* **Date**: select an option from the menu
* **CWE**: type in an exact match of a CWE
* **Severity**: select one or more Severities from the menu
* **Last Reviewed**: select an option from the menu
* **Last Status Update**: select an option from the menu
* **Mitigated Date**: select an option from the menu
* **Reported By**: select one or more Users from the menu
* **Product Type**: select one or more Product Types from the menu
* **Product**: select one or more Products from the menu
* **Product Lifecycle**: select one or more Product Lifecycle states from the menu
* **Engagement**: select one or more Engagements from the menu
* **Engagement Version**: type in an exact match of an Engagement Version
* **Test Type**: select one or more Test from the menu
* **Test Version**: type in an exact match of a Test Version
* **Active**: Yes/No
* **Verified**: Yes/No
* **Duplicate**: Yes/No
* **Mitigated**: Yes/No
* **Out Of Scope**: Yes/No
* **False Positive**: Yes/No
* **Has Components**: Yes/No
* **Has Notes**: Yes/No
* **File Path Contains**: type in a partial match of a File Path
* **Unique ID From Tool**: type in an exact match of a Unique ID From Tool
* **Vulnerability ID From Tool**: type in an exact match of a Vulnerability From Tool
* **Vulnerability ID**: type in an exact match of a Vulnerability
* **Service Contains**: type in a partial match of a Service
* **Parameter Contains**: type in a partial match of an Parameter
* **Payload Contains**: type in a partial match of an Payload
* **Risk Accepted**: Yes/No
* **Has Group**: select an option from the list
* **Planned Remediation Date**: select an option from the list
* **Planned Remediation Version**: type in a Planned Remediation Version
* **Reviewers**: select one or more Users from the list
* **Endpoint Host Contains**: type in a partial match of an Endpoint Host
* **Outside of SLA**: Yes/No
* **Effort For Fixing**: select an option from the list
* **Has Tags**: Yes/No
* **Tags**: type in one or more partial matches of Finding tags, separated by commas
* **Tag Contains**: type in one or more partial matches of Finding tags, separated by commas
* **Does Not Have Tags: type in one or more exact matches of Finding tags to ignore, separated by commas**
* **Tag Does Not Contain**: type in one or more partial matches of Finding tags, separated by commas
* **Test Tags**: type in one or more exact matches of tags, separated by commas
* **Test Does Not Have Tags**: type in one or more exact matches of tags to ignore, separated by commas
* **Engagement Tags**: type in one or more exact matches of tags, separated by commas
* **Engagement Does Not Have Tags**: type in one or more exact matches of tags to ignore, separated by commas
* **Product Tags**: type in one or more exact matches of tags, separated by commas
* **Product Does Not Have Tags**: type in one or more exact matches of tags to ignore, separated by commas

### Endpoint Tile

* **Protocol Contains**: type in a partial match of a Protocol from the menu
* **User Info Contains**: type in a partial match of User Info from the menu
* **Host Contains**: type in a partial match of a Host from the menu
* **Port Contains**: type in a partial match of a Port from the menu
* **Path Contains**: type in a partial match of a Path from the menu
* **Query Contains**: type in a partial match of a Query from the menu
* **Fragment Contains**: type in a partial match of a Fragment from the menu
* **Product**: select one or more Products from the menu
* **Has Tags**: Yes/No
* **Tags**: type in one or more exact matches of tags, separated by commas
* **Tag Contains**: type in one or more partial matches of tags, separated by commas
* **Does Not Have Tags**: type in one or more exact matches tags to ignore, separated by commas
* **Tag Does Not Contain**: type in one or more partial matches of tags to ignore, separated by commas

### SLA Violation Tile

* **Days Before Expiration**: select an option from the menu
* **Include All Products**: Yes/No
* **Included Products**: select one or more Products from the menu

### Scan Time Violation Tile

* **Days Since Last Scan**: select an option from the menu
* **Include All Products**: Yes/No
* **Included Products**: select one or more Products from the menu

### Product Grade Tile

* **Product Grade**: select a single Product Grade from the menu
* **Comparison Operator**: select a Comparison Operator from the menu, related to Product Grade
* **Include All Products**: Yes/No
* **Included Products**: select one or more Products from the menu
