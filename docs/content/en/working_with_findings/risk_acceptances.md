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

![](https://downloads.intercomcdn.com/i/o/tj2vh1ie/1204636819/b9dd073262332f1944c0cfacfd2a/AD_4nXfy5v0NTmT2-wzbXdnxwNZtiYLk18QuyFJM0t6uhv_8RToYIsjB0d9jKIKeYoVF2jEIL_XSnYVgGsnMP2D5EdkyuJg0ilLdjR--1QhI_l81yP8yPmmlpO4UkUlANShbUsvOT6VqSFD5jNKPAqenonX7GnSM?expires=1729720800&signature=1115c41a7aa8dec8ac1854137467fcba167b85c3b479cdd97a625b19a75ab611&req=dSInEs99m4leUPMW1HO4zeaRgo0pTnme8fBYAl4WbyXDzvLafNSr2o%2BGMLsB%0AcNM2%0A)## 


![](https://downloads.intercomcdn.com/i/o/tj2vh1ie/1204636820/11762eeeaf483c78d521d7446ca1/AD_4nXe9Mit2Y220ayEJR0rbzABrWY24WQ1LUfZJCZgBsM_0V24ZMJcWGr6U6REZYP2PMGmSuN0Dk60kT_2LSDkG9Jo2XC3t_uumxIOFlWJ7Qg4f7clfC1S_DZWvy811Gzrj4dTm1WJzR1Z7XIkVBgZn5jXrjTt1?expires=1729720800&signature=1cf2c1b627251a1063864290fc3e005c24c43ac5caddc7721ae5e2a5e9270fd7&req=dSInEs99m4ldWfMW1HO4zRkGaztiDiOJcg%2Bp%2FR3%2FI2bFU4DBwLfqHSfAvvJw%0ACeTp%0A)
To create a New Risk Acceptance, complete the Add to New Risk Acceptance form on a Finding you wish to Risk Accept.


# 


![](https://downloads.intercomcdn.com/i/o/tj2vh1ie/1204636818/9419eeece88da46563d490017da3/AD_4nXcEwS6HnTQUszfs2jHj7pEXXZnDqskbX2sVw-pWhBfvuuzr5fowhUuz53rMWLbkLJCEg0jMSA-41MIgLXoksJEDHswtmkX5gExVwSmYme6KqR4Y4Pav-vWPz47vJ6fVvj1v7ZE4VqEEieLQNkuIVYVevMI?expires=1729720800&signature=3a873d6c6f98ce933165f4225de1333a537f3c67f38936f57a7328af1d7262a3&req=dSInEs99m4leUfMW1HO4zWGsfrz%2FC8qjBdsvsU%2BkGkqvMVSR%2FYsJZwwE%2FuT0%0AoDt6%0A)1. Create a **Name** for the Risk Acceptance.
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



![](https://downloads.intercomcdn.com/i/o/tj2vh1ie/1204640131/447a5095df2fb468d8fbe43d4a1d/Screenshot+2024-10-04+at+2_23_38%E2%80%AFPM.png?expires=1729720800&signature=127f9a6b5dd30515098838117a5fbe61b2464fadfa93d6f630c9fd8c39b48ca9&req=dSInEs96nYBcWPMW1HO4zT2bUZxwU%2FbqrPBD4qx8knM3HZEXsp9ooOlsDdne%0A5t8q%0A)
