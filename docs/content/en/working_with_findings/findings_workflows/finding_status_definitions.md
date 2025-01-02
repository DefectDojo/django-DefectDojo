---
title: "Finding Status Definitions"
description: "A quick reference to Finding status: Open, Verified, Accepted.."
weight: 2
---

Each Finding created in DefectDojo has a Status which communicates relevant information. Statuses help your team keep track of their progress in resolving issues.

Each Finding status has a context\-specific meaning which will need to be defined by your own team. These are our suggestions, but your team's usage may vary.

## **Active** **Findings**

‘This Finding has been discovered by a scanning tool.’

By default, any new Finding created in DefectDojo will be labeled as **Active**. Active in this case means ‘this is a new Finding that DefectDojo has not recorded on a past import’. If a Finding has been Mitigated in the past, but appears in a scan again in the future, the status of that Finding will reopen to reflect that the vulnerability has returned.

## **Verified Findings**

‘This Finding has been confirmed by our team to exist.’

Just because a tool records a problem does not necessarily mean the Finding requires engineering attention. Therefore, new Findings are also labeled as **Unverified** by default. 

If you’re able to confirm that the Finding does exist, you can mark it as **Verified**.

If you don’t need to manually verify each Finding, you can automatically mark them as Verified during import, or disregard this Status.

## **Open Findings**

‘There is work to be done on these Findings.’

Once a Finding is **Active**, it will be labeled as an **Open** Finding, regardless of whether or not it has been **Verified.**

Open Findings can be seen from the **Findings \> Open Findings** view of DefectDojo.

## **Closed Findings**

'The Vulnerability recorded here is no longer active’.

Once the work on a Finding is complete, you can manually Close it from the Close Findings option. Alternatively, if a scan is re\-imported into DefectDojo which does not contain a previously\-recorded Finding, the previously\-recorded Finding will automatically close.

## **Under Review**

‘I have sent this Finding to one or more team members to look at.’

When a Finding is Under Review, it needs to be reviewed by a team member. You can put a Finding under review by Selecting **Request Peer Review** from the Finding’s drop\-down menu.

![image](images/Finding_Status_Definitions.png)

## **Risk Accepted**

‘Our team has evaluated the risk associated with this Finding, and we’ve agreed that we can safely delay fixing it.’

Findings cannot always be remediated or addressed for various reasons. You can add a Risk Acceptance to a Finding with the Add Risk Acceptance option. Risk Acceptances allow you to upload files and enter notes to support a Risk Acceptance decision.

Risk Acceptances have expiry dates, at which time you can reevaluate the impact of the Finding and decide what to do next.

For more information on Risk Acceptances, see our [Guide](../risk_acceptances).

## **Out Of Scope**

‘This Finding was discovered by our scanning tool, but detecting this kind of vulnerability was not the direct goal of our test.’

When you mark a Finding as Out Of Scope, you are indicating that it is not directly relevant to the Engagement or Test it is contained within.

If you have a testing and remediation effort related to a specific aspect of your software, you can use this Status to indicate that this Finding is not part of your effort.

## **False Positive**

‘This Finding was discovered by our scanning tool, but after reviewing the Finding we have discovered that this reported vulnerability does not exist.’

Once you’ve reviewed a Finding, you might discover that the vulnerability reported does not actually exist. The False Positive status allows DefectDojo to keep track of this information, and future imports will also apply the False Positive status to this Finding.

If a different scanning tool finds a similar Finding, it will not be recorded as a False Positive. DefectDojo can only compare Findings within the same tool to determine if a Finding has already been recorded.

## **Inactive**

‘This Finding was discovered previously but it was either mediated or does not require immediate attention.’

If a Finding is marked as Inactive, this means that the issue currently has no impact on the software environment and does not need to be addressed. This status does not necessarily mean that the issue has been resolved.
