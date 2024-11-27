---
title: "Import Scan Form"
description: ""
---

If you have a brand new DefectDojo instance, the Import Scan Form is a logical first step to learn the software and set up your environment. From this form, you upload a scan file from a supported tool, which will create Findings to represent those vulnerabilities. While filling out the form, you can decide whether to:



* Store these Findings under an existing Product Type / Product / Engagement **or**
* Create a new Product Type / Product / Engagement to store these Findings

It’s easy to reorganize your Product Hierarchy in DefectDojo, so it’s ok if you’re not sure how to set things up yet. 



For now, it’s good to know that **Engagements** can store data from multiple tools, which can be useful if you’re running different scans concurrently.



# Accessing the Import Scan Form


The Import Scan form can be accessed from multiple locations:


1. Via the **Import \> Add Findings** menu option on the sidebar
2. From a **Product’s** **‘⋮’ (horizontal dots) Menu**, from a **Products Table**
3. From the **⚙️Gear Menu** on a **Product Page**


# Completing the Import Scan Form



![image](images/import_scan_ui.png)
The Import Scan form will create a new Test nested under an Engagement, which will contain a unique Finding for each vulnerability contained within your scan file.



The Test will be created with a name that matches the Scan Type: e.g. a Tenable scan will be titled ‘Tenable Scan’.



## Form Options


* **Scan File:** by clicking on the Choose button, you can select a file from your computer to upload.
* **Scan Date (optional):** if you want to select a single Scan Date to be applied to all Findings that result from this import, you can select the date in this field.   
If you do not select a Scan Date, Findings created from this report will use the date specified by the tool. SLAs for each Finding will be calculated based on their date.
* **Scan Type:** select the tool used to create this data.
* **Product Type / Product / Engagement Name:** select the Product Type, Product, and Engagement Name which you want to create a new Test under. You can also create a new Product Type, Product and/or Engagement at this time if you wish to, by entering the names of the objects that you want to create.
* **Environment:** select an Environment that corresponds to the data you’re uploading.
* **Tags:** if you want to use tags to further organize your Test data, you can add Tags using this form. Type in the name of the tag you want to create, and press Enter on your keyboard to add it to the list of tags.
* **Process Findings Asynchronously**: this field is enabled by default, but it can be disabled if you wish. See explanation below.

## Process Findings Asynchronously


When this field is enabled, DefectDojo will use a background process to populate your Test file with Findings. This allows you to continue working with DefectDojo while Findings are being created from your scan file.



When this field is disabled, DefectDojo will wait until all Findings have been successfully created before you can proceed to the next screen. This could take significant time depending on the size of your file.



This option is especially relevant when using the API. If uploading data with Process Findings Asynchronously turned **off**, DefectDojo will not return a successful response until all Findings have been created successfully, 



## Optional Fields


* **Minimum Severity**: If you only want to create Findings for a particular Severity level and above, you can select the minimum Severity level here. All vulnerabilities with lower severity than this field will be ignored.
* **Active**: if you want to set all of the incoming Findings to either Active or Inactive, you can specify that here. Otherwise, DefectDojo will use the tool’s vulnerability data to determine whether the Finding is Active or Inactive. This option is relevant if you need your team to manually triage and verify Findings from a particular tool.
* **Verified**: as with Active you can set the new set of Findings to either Verified or Unverified by default. This depends on your workflow preferences. For example, if your team prefers to assume Findings are verified unless proven otherwise, you can set this field to True.
* **Version, Branch Tag, Commit Hash, Build ID, Service** can all be specified if you want to include these details in the Test.
* **Source Code Management URI** can also be specified. This form option must be a valid URI.
* **Group By:** if you want to create Finding Groups out of this File, you can specify the grouping method here.


## Next Steps


Once your upload has completed, you should be redirected to the Test Page which contains the Findings found in the scan file. You can start working with those results right away, but feel free to consult the following articles:



* Learn how to organize your Product Hierarchy to manage different contexts for your Findings and Tests: **[Core Data Classes](https://support.defectdojo.com/en/articles/8545273-core-data-classes-overview)**.
* Learn how to add new Findings to this test: **Reimport Data To Extend a Test**
