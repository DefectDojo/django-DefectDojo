---
title: "Risk Acceptances"
description: "Leveraging Risk Acceptances in DefectDojo OS"
audience: opensource
weight: 2
---

**Risk Acceptances** are a special status that can be applied to Findings to formally document and operationalize the decision to acknowledge them without immediately remediating them.

Contrary to DefectDojo Pro, Risk Acceptances in OS DefectDojo are not independent objects. Rather, Risk Acceptances are only linked to Engagements. As such, they can only contain Findings from the Engagement they live in. If 3 instances of the same Finding appear in a Test in 3 different Engagements, 3 different Risk Acceptances will be required to fully accept those Findings.

### Accessing Risk Acceptances 

Risk Acceptances include Findings that are particular to the Test(s) within each Engagement. As such, they can be accessed from the Engagement that contains the Test those Findings are from. 

![image](images/OS_RA_image1.png)

A complete list of individual risk-accepted Findings is viewable in the **Risk Accepted Findings** submenu of the **Findings** section in the sidebar.

![image](images/OS_RA_image2.png)

## Creating Risk Acceptances 

When a Finding is Risk Accepted, the following will occur: 
- The Finding’s status will no longer be “Active” but it will remain queryable, reportable, and auditable.
- The Finding’s status will be changed to “Risk Accepted.”
- The Finding will no longer be counted toward Metrics, but will still appear within the Test it originated from.

Findings can be Risk Accepted in one of two ways: They can either be manually added to a **Full Risk Acceptance**, or by using the **Simple Risk Acceptance** workflow.

### Full Risk Acceptances

A Full Risk Acceptance allows Users to accept the risk of multiple Findings within an Engagement and bundle them into a single unit. If organizational policy requires formal, documented risk acceptances, or Users wish to trigger certain actions once a Risk Acceptance expires, Full Risk Acceptances are the best choice, as they capture the internal decision-making process and can serve as a source of truth.

Each Full Risk Acceptance adds additional context, such as:
- The name of the Risk Acceptance.
- The owner of the Risk Acceptance.
- The security recommendation and decision regarding how to handle the Finding(s).
- Any proof associated with the recommendation or decision.
- Details regarding the recommendation or decision.
- The User who accepts the risk associated with the decision.
- The expiration date.
    - Whether the Finding’s status will return to “Active” upon expiration.
    - Whether the SLA will restart upon expiration.

Expiration is unique to Full Risk Acceptances, and allows any Findings that have been Risk Accepted to be re-examined at an appropriate time. Once a Full Risk Acceptance expires, any Findings will be set to Active again. If you don’t specify a date, the Default Risk Acceptance / Default Risk Acceptance Expiration date will be used from the System Settings page.

Importantly, as Full Risk Acceptances are restricted to individual Engagements, there is no single section in which to view all Full Risk Acceptances. They can only be viewed within the respective Engagement that includes the Findings that the Full Risk Acceptance contains.

#### How to Create a Full Risk Acceptance

In order to create a Full Risk Acceptance, navigate to the Engagement view and click the **+** symbol in the Risk Acceptance box. 

![image](images/OS_RA_image3.png)

From there, fill out the details of the Full Risk Acceptance and select the Findings to be included. **Accepted Findings** contains a dropdown list of all available Findings to be added to the Risk Acceptance. The list of Findings within the Engagement will appear in descending order of severity (Critical Findings at the top, Low Findings at the bottom). If a Finding has been previously Risk Accepted, it will not appear in the dropdown list. 

Once completed, the Full Risk Acceptance will appear within the Risk Acceptance box in the Engagement view. 

A Risk Acceptance can also be created by clicking the **Add Risk Acceptance** button from within an individual Finding's ⋮ kebab menu. 

![image](images/OS_RA_image7.png)

#### Interacting with Full Risk Acceptances

Once a Full Risk Acceptance has been created, it can be opened to view the Findings that were added to it as well as any details that were input when it was created (e.g., the date, owner, decision, expiration, etc.).

To remove a Finding from a Full Risk Acceptance, click the **Remove** button within the Findings Accepted table. 

![image](images/OS_RA_image8.png)

The Full Risk Acceptance's view also includes a table at the bottom for all other Findings from Tests within that Engagement. From there, you may select additional Findings and add them to that Full Risk Acceptance. 

Additionally, there is a Notes function that allows Users to include additional context to the Full Risk Acceptance. All public notes will appear in any Reports that are generated for the Full Risk Acceptance, whereas notes that are toggled as **Private** will not appear in reports. 

Importantly, if a Full Risk Acceptance is deleted entirely, the Findings within will have their status automatically reverted to “Active.”

### Simple Risk Acceptances

While Full Risk Acceptance is enabled by default, Simple Risk Acceptance must be enabled manually, either upon the creation of an Asset or within the Asset’s settings.

![image](images/OS_RA_image4.png)

A Simple Risk Acceptance can be performed in either one of two ways: 
1. Within a Test view using the Bulk Edits menu that appears after selecting one or more Findings from within the Findings table. 

![image](images/OS_RA_image5.png)

2. Clicking **Accept Risk** from within an individual Finding’s ⋮ kebab menu. 

![image](images/OS_RA_image6.png)

Once a Finding has been Simple Risk Accepted, it will still appear in the Test's Findings table, but the status will be changed to **Inactive, Risk Accepted.** A complete list of individual risk-accepted Findings is viewable in the **Risk Accepted Findings** submenu of the **Findings** section in the sidebar.

If you Simple Risk Accept a Finding and later wish to add it to a Full Risk Acceptance, the Risk must be unaccepted prior to adding it to a Full Risk Acceptance. 

### Risk Acceptance Best Practices 

As a standard practice, it is generally preferable to use either Full Risk Acceptances or Simple Risk Acceptances exclusively, rather than leveraging both.

For example, if Full Risk Acceptances are the default approach, if a Finding is Simple Risk Accepted, it may cause confusion if there is no associated Full Risk Acceptance that contains the affected Finding. Similarly, if Findings are typically Simple Risk Accepted, it may also create confusion to then add some Findings to a Full Risk Acceptance when there are no such objects for most other Findings. 
