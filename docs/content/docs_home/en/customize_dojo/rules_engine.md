---
title: "Rules Engine Automation"
description: "Working with Rules Engine Automation"
weight: 1
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Rules Engine is a DefectDojo Pro-only feature.</span>

DefectDojo's Rules Engine allows you to build custom workflows and bulk actions to handle Findings and other objects.  Rules Engine allows you to build automated actions that are triggered when an object matches a Rule.

Rules Engine can only be accessed through the [Pro UI](/en/about_defectdojo/ui_pro_vs_os/).

Currently, Rules can only be created for Findings, however more object types will be supported in the future.

Rules always need to be manually triggered from the **All Rules** page.  When a rule is triggered, it will be applied to all existing Findings that match the filter conditions set.

## Possible Rule Actions
Each Rule can apply one or more of these changes to a Finding when it is triggered successfully (i.e. matches the set Filter conditions).

* Modify or append one or more informational fields on a Finding, including Title, Description, Severity, CVSSv3 Vector, Active, Verified, Risk Accepted, False Positive, Mitigated
* Set a User to Review a Finding
* Assign a Group as Owners for a Finding
* Add Tags to a Finding
* Add a Note to a Finding
* Create an Alert in DefectDojo with custom text

### Filter conditions
Rules are automatically triggered when a Finding meets specific Filter conditions. For more information on Filters that can be used to create Rule Actions, see the [Filter Index](/en/working_with_findings/organizing_engagements_tests/filter_index/) page.

## Creating a New Rule
Start this process from the New Rule page.  In the [Pro UI](/en/about_defectdojo/ui_pro_vs_os/), under **Manage Category**, Expand the **Rules Engine** dropdown and click **+ New Rule**.

![image](images/rules_engine_1.png)

### Step 1: Label your Rule
Enter a Label as the identifier for the new rule, and click Next.

![image](images/rules_engine_2.png)

### Step 2: Set trigger conditions with a Filter
You will see an All Findings table.  Using the All Findings Table, set the Filter conditions to filter the set of Findings that you want your rule to apply to.  For more information on applying Filters to a table, see [our guide to the Pro UI](/en/about_defectdojo/ui_pro_vs_os/#navigational-changes).

The table will preview the list of existing Findings that you have filtered.

For example, in this screenshot we are filtering for all Findings that are in 'Product One'.  Once we apply this filter (by clicking outside of the Filters menu), it will be added to our list of applicable Filters.

![image](images/rules_engine_3.png)

In the screenshot above, all Findings that are in the Product 'Product One' will have actions taken on them.

Once you have a set of Filters that you want to apply, Click the Next Button.

### Step 3: Set the Rule Actions 
From the **Action** dropdown, select the Action that you want to apply to a Finding that matches all filters from Step 2.  Multiple Actions can be applied.

You can set an additional Conditional Values which allow you to take additional actions, if certain criteria are met.  

![image](images/rules_engine_4.png)


For example, in the screenshot above we have 4 Rule Actions set.  Two of these actions are Conditional.

All Findings which match the filter conditions will trigger these Non-Conditional Actions:

* The Finding will be assigned to user group 'Group 1'
* The Finding will be tagged with `all_group_1`

Any Findings that match the filter conditions, plus these **additional** conditions will trigger these Conditional Actions in addition to the two Non-Conditional Actions listed above:

* **if the Finding has Critical Severity**, it will be tagged with `critical_group_1`.
* **if the Finding has High Severity**, it will be tagged with `high_group_1`.

### Step 4 - Preview your Rule

The Rule Preview displays all of the Findings that will be changed by this rule once it is run, along with a preview of the Actions taken.  Confirm that you are happy with the proposed changes, and Click Submit to save your rule. 

If you do not believe that this rule was applied correctly, you can Select the Back Button and go back to any of the previous steps. 

![image](images/rules_engine_5.png)

For example, in the screenshot above we have a list of Findings that will be affected by the Rule once it is run.  We can see that new Tags and Owners will be applied to each of these Finding from the columns on the right of the Findings list.

You will be prompted again to confirm that you want your Rule to be created.  Note that the **Rule will not be applied immediately**, and must be triggered manually.

## Running a Rule
From the All Rules page, you can select a Rule you wish to run.  Click on the title of the rule to view it in more detail.

![image](images/rules_engine_6.png)

On this page, you can see detailed information about this rule under **Metadata**, including information on when the rule was last triggered.  You can also see a preview of any Findings that will be affected by a new run of this Rule, underneath **Rule Preview**.

To run the Rule, click the green Run Rule button.  Once you confirm that you want to run the rule, a message will appear that the rule is queued to run. in the background.

Once the Rule has successfully finished Running, the number of Items Changed will be updated in the Rule Metadata section of the Rule description.

## Rule Metadata Reference
* **Rule For**: the objects governed by the Rule.
* **Rule Name**: the name of the Rule.
* **Filters**: the number of Filters applied by this Rule.
* **Actions**: the number of Actions taken by this Rule.
* **Owner**: the User who created this Rule.
* **Status**: the Status report of the last time this Rule executed.  
    'E' = 'Error', 'R' = 'Running', 'S' = 'Success'.
* **Last Run**: the timestamp of the last time this Rule was executed.
* **Items Changed:** count of objects that were changed on the last rule execution.
* **Items Skipped:** count of objects that were skipped by the last rule execution.  If a filtered object already matches the 'result' of a Rule Actions applied to it (for example, if it already has the Tags that would be applied by a Rule Action), the object will simply be skipped.