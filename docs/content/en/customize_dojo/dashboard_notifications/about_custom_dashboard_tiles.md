---
title: "Custom Dashboard Tiles"
description: "How to make Dashboard Tiles work for you, with examples"
weight: 2
---

Dashboard Tiles are customizable sets of filters for your DefectDojo instance, which can be added to your 🏠 **Home** dashboard. Tiles are designed to provide relevant information and speed up navigation within DefectDojo.

![image](images/About_Custom_Dashboard_Tiles.png)

Tiles can:

* Act as shortcuts for particular sets of Findings, Products, or other objects
* Visualize relevant metrics related a Product, Engagement or other components of the [Product Hierarchy](/en/working_with_findings/organizing_engagements_tests/product_hierarchy/)
* Provide alerts on particular activity, track SLA Violations, failing imports or new Critical Findings

Tile Filters set a narrower focus for any tile you want to create. Each Tile has a different set of relevant filters which can be selected.

Note that only Superusers can add or edit Dashboard Tiles.

## Tile Components

Each Tile contains four main components:

![image](images/About_Custom_Dashboard_Tiles_2.png)

2. **A count of each object** that meets the Tile’s filter conditions. For example, a Findings Tile will count the number of Findings filtered by the Tile.
3. **A customizable Header** which can be set to describe the function of the tile.
4. **A customizable Footer** which brings you to the related list of objects. For example, a Findings Tile’s footer will bring you to a list of Findings filtered by the Tile.

## Add / Edit Dashboard Tiles

Custom Dashboard Tiles can be added, edited or deleted by any user with **Superuser** Permissions.

New Dashboard tiles can be added by opening the **+** (plus icon) menu on the Dashboard. New Dashboard tiles will always be created at the bottom of the Dashboard Tiles section.

![image](images/How-To_Add,_Edit_or_Delete_Dashboard_Tiles.png)

Select the kind of Tile you want to add, which will then bring you to the Add Dashboard Tile form.

If you wish to **edit** a Dashboard Tile, you can click the Header of the Tile, which will also open the Dashboard Tile form.

### Display Options

From here you can set your Dashboard Tile’s options:

![image](images/How-To_Add,_Edit_or_Delete_Dashboard_Tiles_2.png)

* Set the **Header** text for your tile **(3)**
* Set the **Footer** text for your tile **(4)**
* Set the **Color** of your icon **(1)**

![image](images/How-To_Add,_Edit_or_Delete_Dashboard_Tiles_3.png)

### Tile Filters
Click the **Tile Filters \+** button at the bottom of the form to expand the Tile Filters menu.  From here you can apply any relevant filtering to the tile.  See the [Tile Index](./#dashboard-tile-index) for more info on what filters can be applied to which tile.

### Dynamic Color Tile

If you want to set your tile to change color based on the associated count of Findings, Products or other objects returned by the filter, you can enable **Dynamic Color Tile** in this menu. The color of the tile Icon will change from Green \-\> Yellow \-\> Red as the object count changes.

* **Dynamic Color Minimum is the bottom of the range. If the Object count is equal to or less than this number, the tile Icon will be set to Green.**
* **Dynamic Color Maximum** is the top of the range. If the Object count is equal to or greater than this number, the tile Icon will be set to Red.
* Any number between the Minimum or the Maximum will set the filter to Yellow.

#### **Example: Critical Findings Count**

Say you wanted to set up a Dynamic Color Tile to track our Critical Findings. You can set your Dynamic Color parameters as follows:

* Set **Dynamic Color Minimum** to 0\. As long as you have 0 active Critical Findings, this tile will be **Green**.
* Set **Dynamic Color Maximum** to 5\. If you have 5 or more Critical Findings active in our environment, the tile will turn **Red** to indicate there’s timely action required to address these Findings.
* If you have 1\-4 Critical Findings in your instance, the filter will be **Yellow** to indicate that we’re not in an ‘emergency’ situation but we should be aware of these Findings.

Of course, your team’s standards and acceptable range for this kind of filter may differ from our example.

#### Inverted Maximum and Minimum

If your Maximum is lower than your Minimum, the range will still compute correctly.

**Example 2: Passing Products Count**

Say you wanted to set up a Tile which tracks your Passing Products with a Dynamic Color. An acceptable count of Passing Products for you is 5 or more, and a ‘failing’ state is 2 or fewer Passing Products.

You can set your **Dynamic Color Maximum** of 2, and a **Dynamic Color Minimum** of 5, the Tile will apply colors as follows:

* If the filter returns 2 Objects or fewer , the tile will be **Red**, indicating that very few of your Products are passing.
* If the filter returns 5 Objects or greater, the tile will be **Green**, indicating that a healthy amount of your Products are passing.
* If the filter returns a value between those two numbers, the tile will be **Yellow**, indicating that a significant, but non\-critical amount of your Products are not passing.

## Dashboard Tile Index

Here is a list summarizing each Dashboard Tile you can add, along with filters that can be applied to the Tile and an example configuration.

### Product, Engagement or Test Tiles

These Tiles allow you to quickly select a list of Products, Engagements or Tests based on the filter parameters you set. You can use this tile for ease in navigation. 

![image](images/About_Custom_Dashboard_Tiles_3.png)

The number on the tile represents the count of objects (Products, Engagement or Tests) contained within the tile’s filter parameters. Clicking the footer will take you to a filtered list of those objects.

#### Example: Monitoring Engagements In Progress

If you want to create a list of your In\-Progress Engagements in DefectDojo, you can set up an Engagement tile which filters for that condition.

* Create an Engagement tile, and from the Tile Filters set **Engagement Status** to **In Progress**.
* To make sure your Tile is accurately labeled, set the Header of your tile to ‘**Engagements In Progress**’.

![image](images/About_Custom_Dashboard_Tiles_4.png)

You could also create Engagement tiles for one or more other states, such as **Blocked** or **Completed**.

#### Product Tile Filters

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

#### Engagement Tile Filters

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

#### Test Tile Filters

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

### Finding Tiles

Finding tiles provide a count of Findings based on the filter parameters you set. As with other tiles, clicking the Footer will take you to a list of the Findings set by the tile.

![image](images/About_Custom_Dashboard_Tiles_5.png)

Using filter parameters you can track Findings in a particular state or time period.

#### Example: Monitoring Critical Findings

If you wanted to be able to quickly access all of your Critical Findings in DefectDojo, you could do this by creating a tile.

* Create a Finding tile, and from the Tile Filters set **Severity** to **Critical**.
* To make sure your Tile is accurately labeled, set the Header of the tile to ‘**Critical Findings**’.

![image](images/About_Custom_Dashboard_Tiles_6.png)

You can add additional filter parameters to make this tile more functional for your use\-case. For example, if you wanted this tile to only track Open Findings (and ignore any Mitigated Findings) you could set the **Active** filter to **Yes.**

#### Finding Tile Filters

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

### Endpoint Tiles

If you need to keep track of particular Endpoints, you can set up a Tile to quickly navigate to a filtered list. This tile can be set up to filter by Host, Product, Tags or other parameters that are relevant to the Endpoints you want to track.

![image](images/About_Custom_Dashboard_Tiles_7.png)

Clicking the footer on this tile brings us to a filtered list of Endpoints which displays their status. DefectDojo will only create and track Endpoints with related vulnerabilities, so this will not include any Endpoints which have no vulnerabilities reported.

#### Example: Monitor All Endpoints With Same Host

If you wanted to use Endpoints to look at vulnerabilities on a certain part of your architecture, regardless of the associated Product, you could use an Endpoint Tile to filter for a particular URL. From there, you could see all Findings associated with that part of your network.

* Create an Endpoint tile. For this example, we are setting the Host Contains field to **‘centralaction\-items’**, as that string is part of many Endpoint URLs in our infrastructure.​
* Set your Header to a title which describes the intended function of your tile. In this example, we used **‘Host: centralaction\-items’**.

![image](images/About_Custom_Dashboard_Tiles_8.png)

#### Endpoint Tile Filters
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

This Tile counts Findings which are at risk of violating SLA. It can be set to track all Products, or specific Products chosen from a list.

#### Example: Findings Approaching SLA Violation

If you want to create a filter for Findings which are within 7 days of SLA expiration, you can set up your filter parameters to track this. When setting the Filter parameters for the SLA Violation tile, set **‘Days Before Expiration’** to **7**. Select either All Products, or a list of specific Products.

Set the Header to describe the filter you’re applying, for example ‘SLA Violation \- 3 Days Or Less’.

![image](images/About_Custom_Dashboard_Tiles_9.png)

Clicking on the footer will bring you to a list of these Findings for you to address. This tile only tracks Active Findings, but will also track Findings with an expired SLA.

#### SLA Violation Tile Filters
* **Days Before Expiration**: select an option from the menu
* **Include All Products**: Yes/No
* **Included Products**: select one or more Products from the menu

### Scan Time Violation Tile

This Tile is used to track specific Products to ensure that new scan data is being added on a regular basis. 

If there are particular Products which you’re scanning on a regular interval, you can use this tile to ensure your tools and imports are running as expected. 

This Tile will return a count and related list of Products which have **not** had new scan data added in the interval you’ve defined.

#### Example: Automation Tracking

If you have scanning tools set to run on a weekly basis, you can use this tile to make sure those automated processes are working correctly.

* From the Tile filters, select the target Products where the scan data will be imported via automation. Set the Days Since Last Scan field to ‘Past Week’.
* Set a descriptive name in the Header which communicates the interval you’re testing.

![image](images/About_Custom_Dashboard_Tiles_10.png)

If you have multiple scanning intervals that you want to monitor, you can set up multiple tiles to track each one.

#### Scan Time Violation Tile Filters
* **Days Since Last Scan**: select an option from the menu
* **Include All Products**: Yes/No
* **Included Products**: select one or more Products from the menu

### Product Grade Tile

This Tile compares the Product Grade of all Products on your instance, so that you can track any Products which do not meet your grading standard.

This tile uses a comparison operator (\<, \=, \<\=, \>\=) to track Products which equal, exceed or fail to meet the Product Grade which you want to monitor.

![image](images/About_Custom_Dashboard_Tiles_11.png)
For more information on how Product Grades are calculated, see our article on [Product Health Grading](/en/working_with_findings/organizing_engagements_tests/product-health-grade/).

#### Example: Track Failing Products

If you want to quickly access Products in your instance which do not meet your Grading standard, you can set up a Tile which handles that calculation. The Grading standard used in this example is ‘Less Than C’: we want our tile to flag any Products with a Grade of D or lower.

* Create a Product Grade Tile. From the Filters list, set the Grade which you consider ‘failing’. In this case we’ll select C.
* In the Filters list, set a **Comparison Operator** to determine the logic used in counting your failing Products. In this case, we’ll select **‘Less Than’**.

![image](images/About_Custom_Dashboard_Tiles_12.png)

As with other Product related Tiles, you can set the Tile to look at All Products in your instance, or only a specific list of Products.

#### Product Grade Tile Filters

* **Product Grade**: select a single Product Grade from the menu
* **Comparison Operator**: select a Comparison Operator from the menu, related to Product Grade
* **Include All Products**: Yes/No
* **Included Products**: select one or more Products from the menu
