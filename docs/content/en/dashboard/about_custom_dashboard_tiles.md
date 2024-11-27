---
title: "About Custom Dashboard Tiles"
description: "How to make Dashboard Tiles work for you, with examples"
---

Dashboard Tiles are customizable sets of filters for your DefectDojo instance, which can be added to your 🏠 **Home** dashboard. Tiles are designed to provide relevant information and speed up navigation within DefectDojo. 



![image](images/About_Custom_Dashboard_Tiles.png)
Tiles can:


* Act as shortcuts for particular sets of Findings, Products, or other objects
* Visualize relevant metrics related to your Product
* Provide alerts on particular activity, track SLA Violations, failing imports or new Critical Findings


# Tile Components


Each Tile contains four main components:



![image](images/About_Custom_Dashboard_Tiles_2.png)
2. **A count of each object** that meets the Tile’s filter conditions. For example, a Findings Tile will count the number of Findings filtered by the Tile.
3. **A customizable Header** which can be set to describe the function of the tile.
4. **A customizable Footer** which brings you to the related list of objects. For example, a Findings Tile’s footer will bring you to a list of Findings filtered by the Tile.


# Types of Dashboard Tiles


There are eight Tiles which you can choose from. These Tiles are explained in more detail below, along with examples of usage.


* **Product Tile**
* **Engagement Tile**
* **Test Tile**
* **Endpoint Tile**
* **SLA Violation Tile**
* **Scan Time Violation Tile**
* **Product Grade Tile**


## Product, Engagement or Test Tile


These Tiles allow you to quickly select a list of Products, Engagements or Tests based on the filter parameters you set. You can use this tile for ease in navigation. 



![image](images/About_Custom_Dashboard_Tiles_3.png)
The number on the tile represents the count of objects (Products, Engagement or Tests) contained within the tile’s filter parameters. Clicking the footer will take you to a filtered list of those objects.




### Example: Monitoring Engagements In Progress


If you want to create a list of your In\-Progress Engagements in DefectDojo, you can set up an Engagement tile which filters for that condition.



* Create an Engagement tile, and from the Tile Filters set **Engagement Status** to **In Progress**.
* To make sure your Tile is accurately labeled, set the Header of your tile to ‘**Engagements In Progress**’.


![image](images/About_Custom_Dashboard_Tiles_4.png)

You could also create Engagement tiles for one or more other states, such as **Blocked** or **Completed**.




## Finding Tiles


Finding tiles provide a count of Findings based on the filter parameters you set. As with other tiles, clicking the Footer will take you to a list of the Findings set by the tile.



![image](images/About_Custom_Dashboard_Tiles_5.png)
Using filter parameters you can track Findings in a particular state or time period.




### Example: Monitoring Critical Findings


If you wanted to be able to quickly access all of your Critical Findings in DefectDojo, you could do this by creating a tile.


* Create a Finding tile, and from the Tile Filters set **Severity** to **Critical**.
* To make sure your Tile is accurately labeled, set the Header of the tile to ‘**Critical Findings**’.


![image](images/About_Custom_Dashboard_Tiles_6.png)

You can add additional filter parameters to make this tile more functional for your use\-case. For example, if you wanted this tile to only track Open Findings (and ignore any Mitigated Findings) you could set the **Active** filter to **Yes.**




## Endpoint Tiles


If you need to keep track of particular Endpoints, you can set up a Tile to quickly navigate to a filtered list. This tile can be set up to filter by Host, Product, Tags or other parameters that are relevant to the Endpoints you want to track.



![image](images/About_Custom_Dashboard_Tiles_7.png)
Clicking the footer on this tile brings us to a filtered list of Endpoints which displays their status. DefectDojo will only create and track Endpoints with related vulnerabilities, so this will not include any Endpoints which have no vulnerabilities reported.




### Example: Monitor All Endpoints With Same Host


If you wanted to use Endpoints to look at vulnerabilities on a certain part of your architecture, regardless of the associated Product, you could use an Endpoint Tile to filter for a particular URL. From there, you could see all Findings associated with that part of your network.


* Create an Endpoint tile. For this example, we are setting the Host Contains field to **‘centralaction\-items’**, as that string is part of many Endpoint URLs in our infrastructure.​
* Set your Header to a title which describes the intended function of your tile. In this example, we used **‘Host: centralaction\-items’**.


![image](images/About_Custom_Dashboard_Tiles_8.png)

## SLA Violation Tile


This Tile counts Findings which are at risk of violating SLA. It can be set to track all Products, or specific Products chosen from a list.




### Example: Findings Approaching SLA Violation


If you want to create a filter for Findings which are within 7 days of SLA expiration, you can set up your filter parameters to track this. When setting the Filter parameters for the SLA Violation tile, set **‘Days Before Expiration’** to **7**. Select either All Products, or a list of specific Products.



Set the Header to describe the filter you’re applying, for example ‘SLA Violation \- 3 Days Or Less’.



![image](images/About_Custom_Dashboard_Tiles_9.png)

Clicking on the footer will bring you to a list of these Findings for you to address. This tile only tracks Active Findings, but will also track Findings with an expired SLA.


## 


## Scan Time Violation Tile


This Tile is used to track specific Products to ensure that new scan data is being added on a regular basis. 



If there are particular Products which you’re scanning on a regular interval, you can use this tile to ensure your tools and imports are running as expected. 



This Tile will return a count and related list of Products which have **not** had new scan data added in the interval you’ve defined.




### Example: Automation Tracking



If you have scanning tools set to run on a weekly basis, you can use this tile to make sure those automated processes are working correctly.


* From the Tile filters, select the target Products where the scan data will be imported via automation. Set the Days Since Last Scan field to ‘Past Week’.
* Set a descriptive name in the Header which communicates the interval you’re testing.


![image](images/About_Custom_Dashboard_Tiles_10.png)

If you have multiple scanning intervals that you want to monitor, you can set up multiple tiles to track each one.




## Product Grade Title


This Tile compares the Product Grade of all Products on your instance, so that you can track any Products which do not meet your grading standard.



This tile uses a comparison operator (\<, \=, \<\=, \>\=) to track Products which equal, exceed or fail to meet the Product Grade which you want to monitor.



![image](images/About_Custom_Dashboard_Tiles_11.png)
For more information on how Product Grades are calculated, see our article on [Product Health Grading](https://support.defectdojo.com/en/articles/9222109-product-health-grading).




### Example: Track Failing Products


If you want to quickly access Products in your instance which do not meet your Grading standard, you can set up a Tile which handles that calculation. The Grading standard used in this example is ‘Less Than C’: we want our tile to flag any Products with a Grade of D or lower.


* Create a Product Grade Tile. From the Filters list, set the Grade which you consider ‘failing’. In this case we’ll select C.
* In the Filters list, set a **Comparison Operator** to determine the logic used in counting your failing Products. In this case, we’ll select **‘Less Than’**.


![image](images/About_Custom_Dashboard_Tiles_12.png)

As with other Product related Tiles, you can set the Tile to look at All Products in your instance, or only a specific list of Products.



# **Next Steps:**


* Learn how to **[Add, Edit or Delete your Dashboard Tiles](https://support.defectdojo.com/en/articles/9548086-add-edit-or-delete-dashboard-tiles)**.
* For more detailed descriptions of Tile Filters, see our **[Tile Filter Index](https://support.defectdojo.com/en/articles/9548086-add-edit-or-delete-dashboard-tiles#h_0339dd313b)**.


