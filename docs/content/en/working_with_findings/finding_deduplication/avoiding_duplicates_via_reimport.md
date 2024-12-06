---
title: "Avoiding Duplicates: Reimport Recurring Tests"
description: ""
---

If you have a CI/CD pipeline, a daily scan process or any kind of repeated incoming report, setting up a Reimport process in advance is key to avoiding excessive duplicates. Reimport collapses the context and Findings associated with a recurring test into a single Test page, where you can review import history and track vulnerability changes across scans.



1. Create an Engagement to store the CI/CD results for the object you’re running CI/CD on. This could be a code repository where you have CI/CD actions set up to run. Generally, you want a separate Engagement set up for each pipeline so that you can quickly understand where the Finding results are coming from.  
​
2. Each CI/CD action will import data to DefectDojo in a separate step, so each of those should be mapped to a separate Test. For example, if each pipeline execution runs an NPM\-audit as well as a dependency scan, each scan result will need to flow into a Test (nested under the Engagement).  
​
3. You do not need to create a new Test each time the CI/CD action runs. Instead, you can **Reimport** data to the same test location.

  
​


# Reimport in action



DefectDojo will compare the incoming scan data with the existing scan data, and then apply changes to the Findings contained within your Test as follows:  
​



## Create Findings


Any vulnerabilities which were not contained in the previous import will be added to the Test automatically as new Findings.  
​



## Ignore existing Findings


If any incoming Findings match Findings that already exist, the incoming Findings will be discarded rather than recorded as Duplicates. These Findings have been recorded already \- no need to add a new Finding object. The Test page will show these Findings as **Left Untouched**.  
​



## Close Findings


If there are any Findings that already exist in the Test but which are not present in the incoming report, you can choose to automatically set those Findings to Inactive and Mitigated (on the assumption that those vulnerabilities have been resolved since the previous import). The Test page will show these Findings as **Closed**.



If you don’t want any Findings to be closed, you can disable this behavior on Reimport:


* Uncheck the **Close Old Findings** checkbox if using the UI
* Set **close\_old\_findings** to **False** if using the API  
​

## Reopen Findings


* If there are any Closed Findings which appear again in a Reimport, they will automatically be Reopened. The assumption is that these vulnerabilities have occurred again, despite previous mitigation. The Test page will track these Findings as **Reactivated**.


If you’re using a triage\-less scanner, or you don’t otherwise want Closed Findings to reactivate, you can disable this behavior on Reimport:


* Set **do\_not\_reactivate** to **True** if using the API
* Check the **Do Not Reactivate** checkbox if using the UI

  
 


# Working with Import History


Import History for a given test is listed under the **Test Overview** header on the **Test** page.



This table shows each Import or Reimport as a single line with a **Timestamp**, along with **Branch Tag, Build ID, Commit Hash** and **Version** columns if those were specified.




![image](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)
## Actions


This header indicates the actions taken by an Import/Reimport.



* **\# created indicates the number of new Findings created at the time of Import/Reimport**
* **\# closed shows the number of Findings that were closed by a Reimport (due to not existing in the incoming report).**
* **\# left untouched shows the count of Open Findings which were unchanged by a Reimport (because they also existed in the incoming report).**
* **\#** **reactivated** shows any Closed Findings which were reopened by an incoming Reimport.

  
 


# Why not simply use Import?


Although both methods are possible, Import should be reserved for **new occurrences** of Findings and Data, while Reimport should be applied for **further iterations** of the same data.



If your CI/CD pipeline runs an Import and creates a new Test object each time, each Import will give you a collection of discrete Findings which you will then need to manage as separate objects. Using Reimport alleviates this problem and eliminates the amount of ‘cleanup’ you’ll need to do when a vulnerability is resolved.



Using Reimport allows you to store each recurring report on the same page, and maintains a continuity of each time new data was added to the Test.



However, if you’re using the same scanning tool in multiple locations or contexts, it may be more appropriate to create a separate Test for each location or context. This depends on your preferred method of organization.



