---
title: "Risk Acceptances"
description: "Adding Simple and Full Risk Acceptances to your Findings"
---

‘Risk Accepted’ is a special status that can be applied to a Finding in two ways:


* **Risk Accepted** can be freely applied as a Status **if ‘Simple Risk Acceptance’** is enabled.
* You can also create **Full Risk Acceptances**, which are objects stored in DefectDojo to capture a risk acceptance decision made by your team.


A **Full Risk Acceptance** is a special object in DefectDojo, used when Active Findings are ‘backlogged’ by your team. Often, both security teams and developer teams will decide when a Risk Acceptance is appropriate. In DefectDojo, your team can create Risk Acceptances which capture the internal decision making process and can be used as a source of truth.



## About Full Risk Acceptances



Each Full Risk Acceptance can store details about the following:


* The Security team’s recommendation to a Product owner or other stakeholder
* Description of the decision made by stakeholders
* The DefectDojo user involved in the decision making process
* One or more Findings governed by the Risk Acceptance

Findings can be added to a Risk Acceptance regardless of the Product, Test or Engagement they are in.



Any Findings associated with a Full Risk Acceptance will be set to **Inactive**, **Risk Accepted**.



Generally, any Risk Acceptances should follow your internal security policy and be re\-examined at an appropriate time. As a result, Risk Acceptances also have expiration dates. Once a Risk Acceptance expires, any Findings will be set to Active again.



## Adding a new Full Risk Acceptance


Risk Acceptances can be added to a Finding in two ways:


* Using the **Bulk Edit** menu, when looking at a list of Findings
* Using the **Add Risk Acceptance** button on an individual Finding

![image](images/Risk_Acceptances.png) 


![image](images/Risk_Acceptances_2.png)
To create a New Risk Acceptance, complete the Add to New Risk Acceptance form on a Finding you wish to Risk Accept.


# 


![image](images/Risk_Acceptances_3.png)
2. Select the **Owner** of the Risk Acceptance \- this is generally meant to be the DefectDojo team member responsible for the decision to Risk Accept the Finding
3. Complete the **Optional Fields** with any relevant information. If you want to set an Expiration Date or a Warning for that Expiration Date, you can do so here as well. If you don’t specify a date, the Default Risk Acceptance / Default Risk Acceptance Expiration days will be used from the **System Settings** page.
4. Select whether you want to **Reactivate** or **Restart SLAs** on any associated Findings once the Risk Acceptance expires.


# Simple Risk Acceptances


If you don’t want to create a Full Risk Acceptance object and would prefer to simply **apply a status of ‘Risk Accepted’ to a Finding**, you can do so through the Bulk Edit menu. This method is called **Simple Risk Acceptance**.



Before you can apply a Simple Risk Acceptance to a Finding, Simple Risk Acceptance will need to be enabled at the Product level. This setting can be found on the **Edit Product Form**. 



## Applying a Simple Risk Acceptance


With one or more Findings selected, open **Bulk Update Actions**. Navigate to **Simple Risk Acceptance Status** and select either **Accept Risk** or **Unaccept Risk**. Once you have submitted the Bulk Update, ‘Risk Accepted’ will be applied to any Findings selected without the need to create a Risk Acceptance object (with an expiration date or additional metadata).




# Locating Risk Accepted Findings


The sidebar in DefectDojo allows you to quickly find any Risk Accepted Findings by opening **Manage \> Risk Acceptances.**  From here you can view the Risk Acceptance objects themselves, or view a list of Risk Accepted Findings.



![image](images/Risk_Acceptances_4.png)
