---
title: "Adding new Findings to a Test via Reimport"
description: ""
---

When a Test is created in DefectDojo (either in advance or by importing a scan file), the Test can be extended with new Finding data.



For example, let’s say you have a CI/CD pipeline, which is designed to send a new report to DefectDojo every day. Rather than create a new Test or Engagement for each ‘run’ of the pipeline, you could have each report flow into the same Test using **Reimport**.




# Reimport: Process Summary


Reimporting data does not replace any old data in the Test, instead, it compares the incoming scan file with the existing scan data in a test to make informed decisions:



* Based on the latest file, which vulnerabilities are still present?
* Which vulnerabilities are no longer present?
* Which vulnerabilities have been previously solved, but have since been reintroduced?


The Test will track and separate each scan version via **Import History,** so that you can check the Finding changes in your Test over time.



![](https://downloads.intercomcdn.com/i/o/1194908628/52e2f3805bfbc2ef483e80f6/AD_4nXd1WNxopcweiK0ewbROIATPwKW6I4wRkMf83VQHOp3VGnwFbx3PIF_dKM_bTXxeRWdyOZRnXvlAIQUX4yPEwb0fg3P6NQZeRWY2qj6JN0T5BRaz2GZXGvbg-hWPmq2fhPCQHGUDdUMhQgFLkYN901McsDSw?expires=1729720800&signature=92270ab31ae91539655a6579d7f0b64bb18780ba93039b9457970b66e20edfbe&req=dSEuEsB%2BlYddUfMW1HO4zXlQLIbdnHicZ5UbPT1ZwpIiIYEWtY3aCewJOpvL%0Ab%2FjM%0A)


# Reimport Logic: Create, Ignore, Close or Reopen


When using Reimport, DefectDojo will compare the incoming scan data with the existing scan data, and then apply changes to the Findings contained within your Test as follows:



## Create Findings


Any vulnerabilities which were not contained in the previous import will be added to the Test automatically as new Findings.



## Ignore existing Findings


If any incoming Findings match Findings that already exist, the incoming Findings will be discarded rather than recorded as Duplicates. These Findings have been recorded already \- no need to add a new Finding object. The Test page will show these Findings as **Left Untouched**.



## Close Findings


If there are any Findings that already exist in the Test but which are not present in the incoming report, you can choose to automatically set those Findings to Inactive and Mitigated (on the assumption that those vulnerabilities have been resolved since the previous import). The Test page will show these Findings as **Closed**.



If you don’t want any Findings to be closed, you can disable this behavior on Reimport:


* Uncheck the **Close Old Findings** checkbox if using the UI
* Set **close\_old\_findings** to **False** if using the API

## Reopen Findings


* If there are any Closed Findings which appear again in a Reimport, they will automatically be Reopened. The assumption is that these vulnerabilities have occurred again, despite previous mitigation. The Test page will track these Findings as **Reactivated**.


If you’re using a triage\-less scanner, or you don’t otherwise want Closed Findings to reactivate, you can disable this behavior on Reimport:


* Set **do\_not\_reactivate** to **True** if using the API
* Check the **Do Not Reactivate** checkbox if using the UI



# Opening the Reimport form


The **Re\-Import Findings** form can be accessed on any Test page, under the **⚙️Gear** drop\-down menu.


## 


![](https://downloads.intercomcdn.com/i/o/1194908627/eb05840e395795550e54466f/AD_4nXfOUJldIKEa6Yr3NsphqeCAnOa-VlBgyLTYw0z_daFCQjNzdt_1way4w0t8nrX2ggjnllNAVqv6SfCn3BTfytYjATb6cf0tb6u-9ccz4QC6Qg8p_21aXACIMF1dTy2LeTSnpYtYwHEos9JKD5Hz7Ui4JUP7?expires=1729720800&signature=522addc1e53490316243b947db3014fcda398cf1a328d60f3473168682d55871&req=dSEuEsB%2BlYddXvMW1HO4zY5Pd0UWoQFJUVi4V0iRH%2B%2BKw1%2BMkgb%2BSEFmSpeX%0Ac54n%0A)## 


The **Re\-import Findings** **Form** will **not** allow you to import a different scan type, or change the destination of the Findings you’re trying to upload. If you’re trying to do one of those things, you’ll need to use the **Import Scan Form**.




# Working with Import History


Import History for a given test is listed under the **Test Overview** header on the **Test** page.



This table shows each Import or Reimport as a single line with a **Timestamp**, along with **Branch Tag, Build ID, Commit Hash** and **Version** columns if those were specified.




![](https://downloads.intercomcdn.com/i/o/1194908626/72dc8e30a9f35b80e50c45d7/AD_4nXdjK_vtcbopS89UxEkLbbTF5yaKjNaEKoEbm15zq6m_yQcs8RTZWhGpD_FzaKFyp3p9ubrHfQPG1Hxa7mCuJN71_eK8f7gpiFRFrtLQavLz04J4odtBoN2HODhX-2bXgdK6hXZTQs5eoKiMU42BWc2aD7_s?expires=1729720800&signature=7e53ae3bd29381e3a20b8fdb72dd909c5271530c278fb5b1827217b0571218fa&req=dSEuEsB%2BlYddX%2FMW1HO4zaYdUMRuJgJFAp64fyc3gN8EIWfxL2bJjLRubpH%2B%0Amq%2Bo%0A)
## Actions


This header indicates the actions taken by an Import/Reimport.


* **\# created indicates the number of new Findings created at the time of Import/Reimport**
* **\# closed shows the number of Findings that were closed by a Reimport (due to not existing in the incoming report).**
* **\# left untouched shows the count of Open Findings which were unchanged by a Reimport (because they also existed in the incoming report).**
* **\#** **reactivated** shows any Closed Findings which were reopened by an incoming Reimport.


# Reimport via API \- special note


Note that the /reimport API endpoint can both **extend an existing Test** (apply the method in this article) **or** **create a new Test** with new data \- an initial call to /import, or setting up a Test in advance is not required.

