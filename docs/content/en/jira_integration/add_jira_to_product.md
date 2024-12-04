---
title: "Add a Connected Jira Project to a Product"
description: "Set up a DefectDojo Product to push Findings to a JIRA board"
---


If you haven't already set up DefectDojo's Jira Configuration, you'll need to start by linking one or more Jira instances to DefectDojo.  
​  
See this guide for more information: [https://support.defectdojo.com/en/articles/8766815\-connect\-defectdojo\-to\-jira](https://support.defectdojo.com/en/articles/8766815-connect-defectdojo-to-jira)



Once a Jira configuration is connected to a Product, Jira and the Product will communicate to do the following:


* Use DefectDojo Findings to create Jira Issues, which automatically contain all relevant Finding information and links
* Bidirectional Sync, allowing for status updates and comments to be created on both the Jira and DefectDojo side.


# Adding a Jira Configuration to a Product


Each Product in DefectDojo has its own settings which govern how Findings are converted to JIRA Issues. From here, you can decide the associated JIRA Project and set the default behaviour for creating Issues, Epics, Labels and other JIRA metadata.



* In the UI, you can find this page by clicking the " **📝 Edit**" button under **Settings** on the Product page (defectdojo.com/product/{id}) \- see below.  
​


![](https://downloads.intercomcdn.com/i/o/856486761/0295eab4cbcddfaa8580113e/Screenshot+2023-10-18+at+12.52.03+PM.png?expires=1729720800&signature=ced06369d81e12da314378ddff554bb9858e56531b1ddb422b1d5afef67c67cd&req=fCUhEsF4modeFb4f3HP0gDRlwxrKQ7C1qGDGvem7%2FE8Fb%2FJraeTPIbL7fcZA%0AaNw%3D%0A)
* You can link to a Product Settings page directly via **yourcompany.**defectdojo.com/product/{id}/settings.​


# List of Jira Settings


Jira settings are located near the bottom of the Product Settings page.



![](https://defectdojo-inc.intercom-attachments-7.com/i/o/856508823/52f747935f1a459e3e86fc8e/hF1hafMVlC5WgEQwsw3pikonDUk2YOTvriOUQ5IwYZSdBziMEMIjH1UU5jax7WBhq0-QMDlJ9XMlLgCLLWZKqpkWnVXCbe94huW0j9f_dIjyqs56_U_HkIfMyz4kTBfd5lVY9ojiSa5vkL27PzECJQk?expires=1729720800&signature=1016af7fb9854a97d063e8efe0fd71fb586dc3347f3800adbf58c7bd63356872&req=fCUhE8l2lYNcFb4f3HP0gPWOml2mPNmyR7jtT%2B5VWWMM%2B4IShk0FMDvNFDHv%0AKsA%3D%0A)
#### **Jira Instance**


If you have multiple instances of Jira set up, for separate products or teams within your organization, you can indicate which Jira Project you want DefectDojo to create Issues in. Select a Project from the drop\-down menu.



If this menu doesn't list any Jira instances, confirm that those Projects are connected in your global Jira Configuration for DefectDojo \- yourcompany.defectdojo.com/jira.



#### **Project key**


This is the Jira Key that you want to use for DefectDojo\-related Issues. You can set this Key to whatever you prefer for identifying DefectDojo Issues (e.g. if you set this key to “DEF” then Jira issues will be keyed as DEF\-1, DEF\-2\.. etc).



![](https://downloads.intercomcdn.com/i/o/856497270/70e6eaf428a1b87f255b750a/Screenshot+2023-10-18+at+1.04.42+PM.png?expires=1729720800&signature=6abc48a2008e34caa111a70203a44977286f8978911352bb4ae510c06736c62f&req=fCUhEsB5n4ZfFb4f3HP0gN9ny5WxtErhtTvx45WDDjl2vYFz0OHr62iGOzKK%0Asdw%3D%0A)
#### **Issue template**


Here you can determine how much DefectDojo metadata you want to send to Jira. Select one of two options:


* **jira\_full**: Issues will track all of the parameters from DefectDojo \- a full Description, CVE, Severity, etc. Useful if you need complete Finding context in Jira (for example, if someone is working on this Issue who doesn't have access to DefectDojo).   
Here is an example of a **jira\_full** Issue:  
​


![](https://downloads.intercomcdn.com/i/o/1124824955/66b150adaeba64b051ec1077/Screenshot+2024-07-25+at+2_03_46+PM.png?expires=1729720800&signature=24a1684a6df4b18b60b9992fa2f30f50b90b9d0ffd4e3070ead8651c375c5ef6&req=dSElEsF8mYhaXPMW1HO4zeHByIiE4CpUnjTjHiKUwy58XRyEJWLONZyASfZl%0A9yVY%0A)
* **Jira\_limited:** Issues will only track the DefectDojo link, the Product/Engagement/Test links, the Reporter and Environment fields. All other fields are tracked in DefectDojo only. Useful if you don't require full Finding context in Jira (for example, if someone is working on this Issue who mainly works in DefectDojo, and doesn't need the full picture in JIRA as well.)  
​  
​**Here is an example of a jira\_limited Issue:**​

![](https://downloads.intercomcdn.com/i/o/1124826652/d84213e22b916af53c7165ca/Screenshot+2024-07-25+at+2_05_20+PM.png?expires=1729720800&signature=b3f08859314e7065b3f6ec4bef26ae49e4863b3afb734b4c79643bb43008e7c0&req=dSElEsF8m4daW%2FMW1HO4zQ5XnsQRrja7Wwx%2FASOHGd4Z1JOMBHolBt2BU7Ym%0A%2Fg75%0A)
#### **Component**


If you manage your Jira project using Components, you can assign the appropriate Component for DefectDojo here.



**Custom fields**


If you don’t need to use Custom Fields with DefectDojo issues, you can leave this field as ‘null’. 



However, if your Jira Project Settings **require you** to use Custom Fields on new Issues, you will need to hard\-code these mappings.



**Jira Cloud now allows you to create a default Custom Field value directly in\-app. [See Atlassian's documentation on Custom Fields](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/) for more information on how to configure this.**




Note that DefectDojo cannot send any Issue\-specific metadata as Custom Fields, only a default value. This section should only be set up if your JIRA Project **requires that these Custom Fields exist** in every Issue in your project.


Follow **[this guide](https://support.defectdojo.com/en/articles/8490775-handling-custom-fields-with-jira-issues)** to get started working with Custom Fields.



**Jira labels**


Select the relevant labels that you want the Issue to be created with in Jira, e.g. **DefectDojo**, **YourProductName..**



![](https://downloads.intercomcdn.com/i/o/856515252/2cb04638b743857035dfdb9f/Screenshot+2023-10-18+at+1.23.40+PM.png?expires=1729720800&signature=7e5276009204e295a410631bdcee70917418272c49a4f4f63d19c6faaae913a3&req=fCUhE8h7n4RdFb4f3HP0gHbMvU3o1kdacSZ2Nc1ZRCBbJmbD2fOk72C%2BJjDp%0ASqM%3D%0A)
#### **Default assignee**


The name of the default assignee in Jira. If left blank, DefectDojo will follow the default behaviour in your Jira Project when creating Issues.



#### Checkbox options


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/856508853/1a12cd990af07464277c71de/yHarpjkd7J_yXpCangrpDyYVtKpiYti-n2ttCdUU07nrxdiganAVBwlVtUO-IIMCCZhUJQ7cwf175TBbqx9o7hGMJqe_a6nseoH5NNy7tI9AIzFoIWpbcJYidspZ_-oE3BgVZr50bd_Pov-TWo67aF8?expires=1729720800&signature=cbcfcc460248cf5f066f4915cc6b7c83ccccf35a918f9618ab238a04385b53ad&req=fCUhE8l2lYRcFb4f3HP0gNME15wuQsqmPhYPiUQHyBoxIJPyVMVZdGuEiZ2s%0AMZs%3D%0A)
#### **Add vulnerability Id as a Jira label**


This allows you to add the Vulnerability ID data as a Jira Label automatically. Vulnerability IDs are added to Findings from individual security tools \- these may be Common Vulnerabilities and Exposures (CVE) IDs or a different format, specific to the tool reporting the Finding. 



#### **Enable engagement epic mapping**


In DefectDojo, Engagements represent a collection of work. Each Engagement contains one or more tests, which contain one or more Findings which need to be mitigated. Epics in Jira work in a similar way, and this checkbox allows you to push Engagements to Jira as Epics.



* An Engagement in DefectDojo \- note the three findings listed at the bottom.  
​


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/856508863/092011ca4636698d8001739b/7KRYqjCnbJFewjwbcicU0_TH1VX9E2driWLX-xd3L-zu1EQxKT0JG_E1LuVpxNFO9G_h4xcpcEHPpFCpWckPBZugNuK3iTdasDWFCp5zoWAtmzOFtFfVd3MMsqOlNHUm6T8Rv0Gd7RdRV4FzuyBcpsA?expires=1729720800&signature=2326ebe98fe0170236c5daeeeb86e436b6409ab329f81978c4a826090b23dec2&req=fCUhE8l2lYdcFb4f3HP0gAHfpVH32nbFvLmNZ74UKjCXKVEWwZhqdey%2BfxEQ%0ANqo%3D%0A)
* How the same Engagement becomes an Epic when pushed to JIRA \- the Engagement's Findings are also pushed, and live inside the Engagement as Child Issues.


![](https://defectdojo-inc.intercom-attachments-7.com/i/o/856508874/70aa304d531b9b75bd147ae3/3YGWST-hUhnmwJVvjB2dOw3zyHV11WIP4RdscZX2LBxtkK1FMiSoIxe2yZ1-eqfVYtezXXKNS3cWhn-KZxQ7g3PkVYktM38yMsU5DomxTXMbIIQgvQpHDu1A2oQcdD0iYm8toGZUgM941kEfxb3Jk6M?expires=1729720800&signature=5781b9ab9165d385fde4f613193964464fab4605794f32588d6d64260810386e&req=fCUhE8l2lYZbFb4f3HP0gGUUkcJqUBbI%2F%2BQ%2FqslyI6BfMNNrkIa20wNQYPJF%0AYNg%3D%0A)


#### **Push All Issues**


If checked, DefectDojo will automatically push any Active and Verified Findings to Jira as Issues. If left unchecked, all Findings will need to be pushed to Jira manually.



#### **Push notes**


If enabled, Jira comments will populate on the associated Finding in DefectDojo, under Notes on the issue(screenshot), and vice versa; Notes on Findings will be added to the associated Jira Issue as Comments. 



#### **Send SLA notifications as comment?**


If enabled, any Issue which breaches DefectDojo’s Service Level Agreement rules will have comments added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.



Service Level Agreements can be configured under **Configuration \> SLA Configuration** in DefectDojo and assigned to each Product.



#### **Send Risk Acceptance expiration notifications as comment?**


If enabled, any Issue where the associated DefectDojo Risk Acceptance expires will have a comment added to the Jira issue indicating this. These comments will be posted daily until the Issue is resolved.




# Testing \& Troubleshooting the Jira integration



## Test 1: Do Findings successfully push to Jira?


In order to test that the Jira integration is working properly, you can add a new blank Finding to the Product associated with Jira in DefectDojo. **Product \> Findings \> Add New Finding.**



Add whatever title severity and description you wish, and then click “Finished”. The Finding should appear as an Issue in Jira with all of the relevant metadata.




If Jira Issues are not being created correctly, check your Notifications for error codes.


* Confirm that the Jira User associated with DefectDojo's Jira Configuration has permission to create and update issues on that particular Jira Project.





## Test 2: Jira Webhooks send and receive updates from DefectDojo


In order to test the Jira webhooks, add a Note to a Finding which also exists in JIRA as an Issue (for example, the test issue in the section above).



If the webhooks are configured correctly, you should see the Note in Jira as a Comment on the issue. 



If this doesn’t work correctly, it could be due to a Firewall issue on your Jira instance blocking the Webhook. 


* DefectDojo's Firewall Rules include a checkbox for **Jira Cloud,** which needs to be enabled before DefectDojo can receive Webhook messages from Jira.




# Next Steps


Learn how to create Jira Issues from your Product with **[this guide](https://support.defectdojo.com/en/articles/8712582-creating-issues-in-jira).**

