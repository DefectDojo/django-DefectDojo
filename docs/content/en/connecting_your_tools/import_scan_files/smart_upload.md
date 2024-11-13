---
title: "Smart Upload"
description: "Automatically route incoming Findings to the correct Product"
---

Smart upload is a specialized importer that ingests reports from **infrastructure scanning tools**, including:



* Nexpose
* NMap
* OpenVas
* Qualys
* Tenable


Smart Upload is unique in that it can split Findings from a scan file into separate Products. This is relevant in an Infrastructure scanning context, where the Findings may apply to many different teams, have different implicit SLAs, or need to be included in separate reports due to where they were discovered in your infrastructure.



Smart Upload handles this by sorting incoming findings based on the Endpoints discovered in the scan. At first, those Findings will need to be manually assigned, or directed into the correct Product from an Unassigned Findings list. However, once a Finding has been assigned to a Product, all subsequent Findings that share an Endpoint or Host will be sent to the same Product.



# Smart Upload menu options


The Smart Upload menu is stored in a collapsible section of the sidebar.



* **Add Findings allows you to import a new scan file, similar to DefectDojo’s Import Scan method**
* **Unassigned Findings lists all Findings from Smart Upload which have yet to be assigned to a Product.**


![](https://downloads.intercomcdn.com/i/o/1194910967/0360afc3606c62b972b29fb0/AD_4nXeghMk_jectcbz_xSEWILQ6TKfMAkJFaYqtLjaeCgjscW0-H0BAM5M2oFQxB4aY4-R6qRcFp4G1-6HP3z9uc7_mICl5JSkxw9lRnKtH4OQBkoRuRYFbtBKMhENVa0HRsuEmH8n-S3vc7s0F_3uTyPOh8Rk?expires=1729720800&signature=182c23fcf2186f97130f369f44608461240088b1545d6053de9e107a589b3ee0&req=dSEuEsB%2FnYhZXvMW1HO4zQ9CTDLAIv7psFxRziJwPE1a%2B1rCBkMxAnkniABG%0AsM3u%0A)

## The Smart Upload Form



The Smart Upload Import Scan form is essentially the same as the Import Scan form. See our notes on the **Import Scan Form** for more details.



![](https://downloads.intercomcdn.com/i/o/1194910970/28b48ec77b1b3fd2ff19d0ea/AD_4nXddw4i_wM6uS34D1FgNp6XXc4jS-LymrQ6-CrkG2zle6mAq9Kwec0c_OrrNiyyBVfm6val4zOm6Luw_NpJcENyk2QX3eGDaPFjQDutPDHq8mbIW5UZ5wTM5va2FfKi9iJszc90_Mmv5aK6SY5wxtN_fuqGF?expires=1729720800&signature=d3665007fd8712695fb627563c2d805a1805cc9b23aaf12c4ddee2bece914413&req=dSEuEsB%2FnYhYWfMW1HO4zXr9jg9CVymHsc8jFHm%2BzRoBsZZTnkdGy3G57DLP%0A1xVl%0A)

# Unassigned Findings


Once a Smart Upload has been completed, any Findings which are not automatically assigned to a Product (based on their Endpoint) will be placed in the **Unassigned Findings** list. The first Smart Upload for a given tool does not yet have any method to Assign Findings, so each Finding from this file will be sent to this page for sorting.



Unassigned Findings are not included in the Product Hierarchy and will not appear in reports, filters or metrics until they have been assigned.



## Working with Unassigned Findings



![](https://downloads.intercomcdn.com/i/o/1194910969/b302152dd308050bc2cabb3f/AD_4nXf4caWaw6HYn1LqY5zv42mQztXQyeNWMmDwQVFRZ7smFzH7rvmZ4NCmDEA3gMVBkGwl51bSvK4sSAf7o8NjtDtuaxVJsC9PLLLbLU5coe0SFHDkoAS_WnqCYSyQbDWmpoNx7dfkLoDQDg9yCj6n8mnuWXqi?expires=1729720800&signature=b68b7f0d6ad8b8761fbd5abd6e390626dbd1a5eefc32911cd11fd94ffb0eb669&req=dSEuEsB%2FnYhZUPMW1HO4zdffFk2MwOJJkdNLPpAJSJFznXtdp%2Fn2TAS3J7sE%0A5jzx%0A)

You can select one or more Unassigned Findings for sorting with the checkbox, and perform one of the following actions:



* **Assign to New Product, which will create a new Product**
* **Assign to Existing Product which will move the Finding into an existing Product**
* **Disregard Selected Findings**, which will remove the Finding from the list


Whenever a Finding is assigned to a New or Existing Product, it will be placed in a dedicated Engagement called ‘Smart Upload’. This Engagement will contain a Test named according to the Scan Type (e.g. Tenable Scan). Subsequent Findings uploaded via Smart Upload which match those Endpoints will be placed under that Engagement \> Test.



## Disregarded Findings


If a Finding is Disregarded it will be removed from the Unassigned Findings list. However, the Finding will not be recorded in memory, so subsequent scan uploads may cause the Finding to appear in the Unassigned Findings list again.

