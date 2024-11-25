---
title: "About Custom Dashboard Tiles"
description: "How to make Dashboard Tiles work for you, with examples"
---

Dashboard Tiles are customizable sets of filters for your DefectDojo instance, which can be added to your 🏠 **Home** dashboard. Tiles are designed to provide relevant information and speed up navigation within DefectDojo. 



![](https://downloads.intercomcdn.com/i/o/1099250898/404bca1e149473568dff200d/crop+ss.png?expires=1729720800&signature=47755368f0a8dbdca29e39525f65564a22b025d67e9b51796368e16018d77ad2&req=dSAuH8t7nYlWUfMW1HO4zXvTdcWRXscEwUdV8OwjwmK0av2hoFfHDgIB50xI%0AUOa8%0A)
Tiles can:


* Act as shortcuts for particular sets of Findings, Products, or other objects
* Visualize relevant metrics related to your Product
* Provide alerts on particular activity, track SLA Violations, failing imports or new Critical Findings


# Tile Components


Each Tile contains four main components:



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245892/8c5490bb29d7b4f030a18ef9/AD_4nXfwA_eCPCfAA35-lMO4ffSlKcvHfRXwVCfFDwhhILI4jjUZMzwGrpuze1U96t0j4qyHvA1qas-A2uyPNjTezdaiyifnvU0ek_M0u6cQrEy_5l6q-VHfH3GOyqKu9xMCwgptjGZ2seU0MFI1Xkcu9dR1kI9h?expires=1729720800&signature=41cd9a22f70dc51017855672d3c10ed400370dce7729030fcacb9a30bbfdb670&req=dSAuH8t6mIlWW%2FMW1HO4zTGMWjMSWgYAIBlHC20hq4YJxOp35zLpAV2AKudY%0AxcC2%0A)1. **A customizable icon**. You can choose an icon and color for the Tile. If you wish, you can also have an icon’s color dynamically change from Green \-\> Yellow \-\> Red based on a value range.
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



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245901/b112e4dad8eb3e5049511371/AD_4nXe9B73G54RwB-G88nnS6oWo96n7-ggZLSbxb03a3DTZFdOgK6pZCJ83ExAHSmm_rWeexZhloErMfRDwdAHXjspkQcOPNths4hog-Q8j-rYMNEZWwG3TL-14qN2aGsbiEDQ4MfL5LEhY59tAjd9KSwMZXKsu?expires=1729720800&signature=d41ebdcc51f9fa05c6b486bca83ed159f1a822d06b30eb37f8db6259bac98588&req=dSAuH8t6mIhfWPMW1HO4zdZejHhWdEsouZLWNlyGuZ1y1tEPtQosw3hz%2FaB8%0ANP1g%0A)
The number on the tile represents the count of objects (Products, Engagement or Tests) contained within the tile’s filter parameters. Clicking the footer will take you to a filtered list of those objects.




### Example: Monitoring Engagements In Progress


If you want to create a list of your In\-Progress Engagements in DefectDojo, you can set up an Engagement tile which filters for that condition.



* Create an Engagement tile, and from the Tile Filters set **Engagement Status** to **In Progress**.
* To make sure your Tile is accurately labeled, set the Header of your tile to ‘**Engagements In Progress**’.


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245912/fbc3e96d9d0fcb6d5f36876a/AD_4nXcAxJNLB-hf2RqEhI0ApBz5EqzvIX-MB9MW_viUJbAPM0NXSIo4kk4ajQbYTctDUFnUpIaSPxbg1eaajU9Ao5hypkRwk9hyyKIlwR2j7htrHO8PnRMzzFqMa0NbnhwvwMi6Z75k-xwtept8fAWjH_q7mSs?expires=1729720800&signature=2ee53595f377fca87ebddf6c7bab00ea121a652ab5dc910d75e9a9764394d220&req=dSAuH8t6mIheW%2FMW1HO4zb%2BODrc%2FMT4hTmvrqb%2F4TR81TT64e2rou8sF0eVH%0AIROi%0A)

You could also create Engagement tiles for one or more other states, such as **Blocked** or **Completed**.




## Finding Tiles


Finding tiles provide a count of Findings based on the filter parameters you set. As with other tiles, clicking the Footer will take you to a list of the Findings set by the tile.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245918/c31bd5f3c478f0794684ed8c/AD_4nXdQgDy4rs29A5pCHDk6WlmKCYsvYajy44FSDTk9aSNPGvozAtvwO7XB8TI0K3xOAk3C1IHNJ1CqaphczS9LofLi2z_omnckucKgoYruz1Sdu_WgAisjkeBfauB_lbxmM837lqYzu4bb17GNO9256vGWB8j2?expires=1729720800&signature=73a1f802703e4119f8ff8ef835fa97f67d6ffb75e8b3b15f65d56645fa578f5a&req=dSAuH8t6mIheUfMW1HO4zePORVTEqkdK7iVtN6jVbCivpEjFJfAY6ZTPQhS2%0ABCjN%0A)
Using filter parameters you can track Findings in a particular state or time period.




### Example: Monitoring Critical Findings


If you wanted to be able to quickly access all of your Critical Findings in DefectDojo, you could do this by creating a tile.


* Create a Finding tile, and from the Tile Filters set **Severity** to **Critical**.
* To make sure your Tile is accurately labeled, set the Header of the tile to ‘**Critical Findings**’.


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245930/9d5a6973c9366eae8dd6d4fd/AD_4nXcOjKshzyqeUHif7KrbeORDKe6FM4G7JvOBPWho1gZ0uR1hifDZXCklCQEUI4ulYkDPqjEUUBNgD5MX_hD7LMbrIP2YGgHEVIdw41o-z3j3C7VXegFZeCzpH5_RBr71aPDKnvRZnSwRqQW2ewml3_xDOp_Q?expires=1729720800&signature=93c118122b6efb5a518410e4a2cbf70556ffef24a1e494a29702c40a51079f03&req=dSAuH8t6mIhcWfMW1HO4zds8nsJ%2BgxUjuYiv%2BPz4Mwo2u3E6reaEF5MS7Xh8%0A902S%0A)

You can add additional filter parameters to make this tile more functional for your use\-case. For example, if you wanted this tile to only track Open Findings (and ignore any Mitigated Findings) you could set the **Active** filter to **Yes.**




## Endpoint Tiles


If you need to keep track of particular Endpoints, you can set up a Tile to quickly navigate to a filtered list. This tile can be set up to filter by Host, Product, Tags or other parameters that are relevant to the Endpoints you want to track.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245937/ad144be9ff33a8b4444ff590/AD_4nXepUNZnVXHIVsbpfvfC2h13w6jXUANG9sQft3ZvHGvSIBqFrbm7AYjHTdAdUXO4IhJHm-oECJLF2YoadKyiS3w5FUPlXBhtimVZs0NCARKipuX-ej0GYxT-i3W2Y07qTmZRYvPUa0OLzQ4seyWPLURoINu2?expires=1729720800&signature=481c9153d83cdea99fab30278788d03f09773f2d7f91c72d37d63757d2ecccd0&req=dSAuH8t6mIhcXvMW1HO4zQSsYYNUM4kbREMXvQBnaYsMgeVUTYM8epzxTFjX%0AHCqU%0A)
Clicking the footer on this tile brings us to a filtered list of Endpoints which displays their status. DefectDojo will only create and track Endpoints with related vulnerabilities, so this will not include any Endpoints which have no vulnerabilities reported.




### Example: Monitor All Endpoints With Same Host


If you wanted to use Endpoints to look at vulnerabilities on a certain part of your architecture, regardless of the associated Product, you could use an Endpoint Tile to filter for a particular URL. From there, you could see all Findings associated with that part of your network.


* Create an Endpoint tile. For this example, we are setting the Host Contains field to **‘centralaction\-items’**, as that string is part of many Endpoint URLs in our infrastructure.​
* Set your Header to a title which describes the intended function of your tile. In this example, we used **‘Host: centralaction\-items’**.


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245947/ac7f51e4310dde5b009dc512/AD_4nXec8wyXhKtfWyVct5icqvYQd1nWnE5iNqtad32P_fhIUOq7k_k7WCo2CiMoWYER9z61ZtohDHWe3OMThel5ZYr4BeV2uq64R4RiMmwh1mNY8OIHryj13mrFuuce3ubctxNoI1BUd3dc2YuOxPC5mD6is2VE?expires=1729720800&signature=72bfb702926099be4ca954ebfa9fca7e549329e16711abe9523273b76efcdc33&req=dSAuH8t6mIhbXvMW1HO4zbw1aZZSF3S5xTEJsUC0GtABK4hktPq3myVycpsp%0AHWm9%0A)

## SLA Violation Tile


This Tile counts Findings which are at risk of violating SLA. It can be set to track all Products, or specific Products chosen from a list.




### Example: Findings Approaching SLA Violation


If you want to create a filter for Findings which are within 7 days of SLA expiration, you can set up your filter parameters to track this. When setting the Filter parameters for the SLA Violation tile, set **‘Days Before Expiration’** to **7**. Select either All Products, or a list of specific Products.



Set the Header to describe the filter you’re applying, for example ‘SLA Violation \- 3 Days Or Less’.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245955/8576606b4010df4c361aa1fa/AD_4nXdGwX6vqdPr4ITjvsq5rJsgO8MwddFTN86EnUq9JKUtibQkXX5xZxVX1IDU3UeZ6WhMIj1dGz_GvxxdgyABTq4rFD0GlDRNvLsqioGJ4NLisrE5xIFjYyHwly9HywdgQc7vuu5WzGzzjv5_4x6vU0FiPutW?expires=1729720800&signature=ac8049bcc6095a8ae237a61e0cbb83eab4c3f1ff71d5b5d8e430f7358b071eb1&req=dSAuH8t6mIhaXPMW1HO4zfBDR3ICj1QmtNLC6aB8BxNW6Qwmak%2FkhLOGcbI4%0Alc78%0A)

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


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245967/9745f21ae3614d9e6406f93a/AD_4nXcVb37xVMoICT7P7w1L8p0VjGYhfGFZZh7m4tO8wfatKebv8pvDhML9sZsuIJ-okh-Oyg9Cahd5M408PtzTbM0ym0qHKwNW99lB9uWiivL9PtD2vPS7NDLG0ZS09ldr7fX-iRB1q5noG0dVGcXIaJ6yvV1P?expires=1729720800&signature=1579ee824aab9d78f6d9125625c48f9162927bb4fb3fc6d861dd707392afa122&req=dSAuH8t6mIhZXvMW1HO4zXyP7F7Ov9ecGvye0gQcHXd8pHK41FspsCfWSlpI%0AUS2o%0A)

If you have multiple scanning intervals that you want to monitor, you can set up multiple tiles to track each one.




## Product Grade Title


This Tile compares the Product Grade of all Products on your instance, so that you can track any Products which do not meet your grading standard.



This tile uses a comparison operator (\<, \=, \<\=, \>\=) to track Products which equal, exceed or fail to meet the Product Grade which you want to monitor.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245976/c64f3cd3a4ba9c82a287d9e4/AD_4nXfzYr-U2z4sQS5f5jzQdW-tGdUKipO2kXoznkzRP8sbGQ9rz_OW0glHfS21OrlrFxkOOVZdkZckwMnbjwrVU4UIxdMzUUjw_PwTMQ9waw6O29lynkHKh1vl2aSkt7vGq4VlIdTutW3qCYyxESOREJI4eMU?expires=1729720800&signature=ed32f49d6a96f11c7871b35f2efdfa70024e72c4397cba6044c772daffd1ca3e&req=dSAuH8t6mIhYX%2FMW1HO4zUlOMyAwa%2FpBhtlqZBy0rpjWQWAVKiIeJ7OUh0%2Ft%0A%2BpJ%2B%0A)
For more information on how Product Grades are calculated, see our article on [Product Health Grading](https://support.defectdojo.com/en/articles/9222109-product-health-grading).




### Example: Track Failing Products


If you want to quickly access Products in your instance which do not meet your Grading standard, you can set up a Tile which handles that calculation. The Grading standard used in this example is ‘Less Than C’: we want our tile to flag any Products with a Grade of D or lower.


* Create a Product Grade Tile. From the Filters list, set the Grade which you consider ‘failing’. In this case we’ll select C.
* In the Filters list, set a **Comparison Operator** to determine the logic used in counting your failing Products. In this case, we’ll select **‘Less Than’**.


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/1099245981/9235ca4f8edd03d04806bd4c/AD_4nXemS4UCV0AVT6i_1iVxwaYBT6aowID4cBzTB5Nmea3Y5HR2YlfmG88L0I7YLoBcXg_0r7CRiK2ZKGCrUlh5uspt7BNu8HHbE30uFedUPqXwAh03n5fMOsiFy5AWe9D7Dm3g1b_8lGJllo_wNU7BAjpGLoR9?expires=1729720800&signature=c78666efc2b09a6f852441e9ded672fb57406790f12dfe7ae6221dc84bba2423&req=dSAuH8t6mIhXWPMW1HO4zUEUoC3vBLQ%2FkccLXG3isEf2Dqdz%2BHIVM%2BRSJM2u%0ANk%2Fh%0A)

As with other Product related Tiles, you can set the Tile to look at All Products in your instance, or only a specific list of Products.



# **Next Steps:**


* Learn how to **[Add, Edit or Delete your Dashboard Tiles](https://support.defectdojo.com/en/articles/9548086-add-edit-or-delete-dashboard-tiles)**.
* For more detailed descriptions of Tile Filters, see our **[Tile Filter Index](https://support.defectdojo.com/en/articles/9548086-add-edit-or-delete-dashboard-tiles#h_0339dd313b)**.


