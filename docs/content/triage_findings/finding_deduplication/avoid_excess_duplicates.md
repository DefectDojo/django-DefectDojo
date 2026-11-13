---
title: "Avoiding Excess Duplicates"
description: ""
weight: 4
aliases:
  - /en/working_with_findings/finding_deduplication/avoiding_duplicates_via_reimport
---
One of DefectDojo’s strengths is that the data model can accommodate many different use-cases and applications. You’ll likely change your approach as you master the software and discover ways to optimize your workflow.

By default, DefectDojo does not delete any duplicate Findings that are created. Each Finding is considered to be a separate instance of a vulnerability. So in this case, **Duplicate Findings** can be an indicator that a process change is required to your workflow.

## When are Duplicate Findings acceptable?

Duplicate Findings are not always indicative of a problem. There are many cases where keeping duplicates is the preferred approach. For example:

* If your team uses and reports on Interactive Engagements. If you want to create a discrete report on a single Test specifically, you would want to know if there’s an occurrence of a Finding that was already uncovered earlier.
* If you have Engagements which are contextually separated (for example, because they cover different repositories) you would want to be able to flag Findings which are occurring in both places.

## Checking for redundant imports

## Step 1: Clean up your excess Duplicates

Fortunately, DefectDojo’s Deduplication settings allow you to mass\-delete duplicates once a certain threshold has been crossed. This feature makes the cleanup process easier. To learn more about this process, see our article on **Finding Deduplication** \<\-link will go here.

### Step 2: Evaluate your Engagements for redundancies

Once you’ve cleaned up your duplicate Findings, it’s a good practice to look at the Asset which contained them to see if there’s a clear culprit. You might find that there are Engagements contained within which have a redundant context.

#### Duplicate or Reused Engagements

Engagements store one or more Tests for a particular testing context. That context is ultimately up to you to define for yourself, but if you see a few Engagements within your Asset which should share the same context, consider combining them into a single engagement.  
​
### Questions to ask when defining Engagement context:

* If I wanted to make a report on this work, would the Engagement contain all of the relevant information I need?
* Are we proactively creating Engagements ahead of time or are they being created ‘ad\-hoc’ by my import process?
* Are we using the right kind of Engagement \- **Interactive** or **CI/CD**?
* What section of the codebase is being worked on by tests: is each repository a separate context or could multiple repositories make up a shared context for testing?
* Who are the stakeholders involved with the Productt, and how will I share results with them?

### Step 3: Check for redundant Tests

If you discover that separate Tests have been created which capture the same testing context, this may be an indicator that these tests can be consolidated into a single Reimport.

DefectDojo has two methods for importing test data to create Findings: **Import** and **Reimport**. Both of these methods are very similar, but the key difference between the two is that **Import** always creates a new Test, while **Reimport** can add new data to an existing Test. It’s also worth noting that **Reimport** does not create duplicate Findings within that Test.

Each time you import new vulnerability reports into DefectDojo, those reports will be stored in a Test object. A Test object can be created by a user ahead of time to hold a future **Import**. If a user wants to import data without specifying a Test destination, a new Test will be created to store the incoming report.

Tests are flexible objects, and although they can only hold one *kind* of report, they can handle multiple instances of that same report through the **Reimport** method. To learn more about Reimport, see our **[article](/import_data/import_intro/reimport/)** on this topic.


## Using Reimport for continual Tests

If you have a CI/CD pipeline, a daily scan process or any kind of repeated incoming report, setting up a Reimport process in advance is key to avoiding excessive duplicates. Reimport collapses the context and Findings associated with a recurring test into a single Test page, where you can review import history and track vulnerability changes across scans.

1. Create an Engagement to store the CI/CD results for the object you’re running CI/CD on. This could be a code repository where you have CI/CD actions set up to run. Generally, you want a separate Engagement set up for each pipeline so that you can quickly understand where the Finding results are coming from.  
​
2. Each CI/CD action will import data to DefectDojo in a separate step, so each of those should be mapped to a separate Test. For example, if each pipeline execution runs an NPM\-audit as well as a dependency scan, each scan result will need to flow into a Test (nested under the Engagement).  
​
3. You do not need to create a new Test each time the CI/CD action runs. Instead, you can **Reimport** data to the same test location.

### Reimport in action

DefectDojo will compare the incoming scan data with the existing scan data, and then apply changes to the Findings contained within your Test as follows:  
​
#### Create Findings

Any vulnerabilities which were not contained in the previous import will be added to the Test automatically as new Findings.  
​
#### Ignore existing Findings

If any incoming Findings match Findings that already exist, the incoming Findings will be discarded rather than recorded as Duplicates. These Findings have been recorded already \- no need to add a new Finding object. The Test page will show these Findings as **Left Untouched**.  
​
#### Close Findings

If there are any Findings that already exist in the Test but which are not present in the incoming report, you can choose to automatically set those Findings to Inactive and Mitigated (on the assumption that those vulnerabilities have been resolved since the previous import). The Test page will show these Findings as **Closed**.

If you don’t want any Findings to be closed, you can disable this behavior on Reimport:

* Uncheck the **Close Old Findings** checkbox if using the UI
* Set **close\_old\_findings** to **False** if using the API  ​

#### Reopen Findings

* If there are any Closed Findings which appear again in a Reimport, they will automatically be Reopened. The assumption is that these vulnerabilities have occurred again, despite previous mitigation. The Test page will track these Findings as **Reactivated**.

If you’re using a triage\-less scanner, or you don’t otherwise want Closed Findings to reactivate, you can disable this behavior on Reimport:

* Set **do\_not\_reactivate** to **True** if using the API
* Check the **Do Not Reactivate** checkbox if using the UI

### Working with Import History

The **Import History** widget on a **Test** page lists every Import and Reimport into that Test, newest first, one row per Import.

![image](images/Avoiding_Duplicates_Reimport_Recurring_Tests.png)

Each row shows:

* **When it ran**, and whether it was an **Import** or a **Reimport**. Hover over or focus the time to see the full timestamp.
* **What it did to the Test's Findings**, as counts:
    * **created**: new Findings created by the Import or Reimport.
    * **closed**: Findings closed because they were missing from the incoming report: by a Reimport, or by an Import with **Close Old Findings** set, which can close Findings in other Tests of the same Engagement or Product.
    * **reactivated**: Closed Findings reopened because they appeared again in the incoming report.
    * **untouched**: Open Findings left unchanged because they also appeared in the incoming report.

  A Reimport that changed nothing reads **No findings changed**.
* **The scan's Version, Branch/Tag, Build ID and Commit Hash**, when they were sent with the Import. A field that was not set is left out. A long value is shortened and the Commit Hash shows its first 12 characters: hover over or focus a value to see all of it.

On a wide widget each Import takes one line; on a narrow one it takes three short lines, and the Branch/Tag and Build ID drop out until there is room. The list scrolls inside the widget, so a Test with many Reimports does not lengthen the page.

#### A Reimport that closed every open Finding

A Reimport that closed Findings and matched none of the existing ones usually means the report was empty or failed to parse, rather than that every vulnerability was fixed. That row is marked **Closed all open findings**. While it is the newest Import in the list, the widget's header reads **Closed all on** and its date; once another Import runs, the header goes back to **Last import** and that Import's date, and the older row keeps its mark. Check the report before you triage the Findings it closed.

Only a Reimport is marked. An Import that closes Findings through **Close Old Findings** is doing what that option asks, so it shows its **closed** count without the warning.

#### Row menu

Each row starts with a menu:

* **View Findings** opens the Findings list filtered to the Findings that Import recorded an action on (created, closed, reactivated or left untouched). The filter shows in the filter bar as **Import ID**, where you can remove it.
* **Copy Commit Hash** copies the full commit hash. It appears only when the Import has one.

### Why not simply use Import?

Although both methods are possible, Import should be reserved for **new occurrences** of Findings and Data, while Reimport should be applied for **further iterations** of the same data.

If your CI/CD pipeline runs an Import and creates a new Test object each time, each Import will give you a collection of discrete Findings which you will then need to manage as separate objects. Using Reimport alleviates this problem and eliminates the amount of ‘cleanup’ you’ll need to do when a vulnerability is resolved.

Using Reimport allows you to store each recurring report on the same page, and maintains a continuity of each time new data was added to the Test.

However, if you’re using the same scanning tool in multiple locations or contexts, it may be more appropriate to create a separate Test for each location or context. This depends on your preferred method of organization.
