---
title: "How-To: Manage Duplicate Findings"
description: "How to discover and correct redundancies in your workflow - using Deduplication, Reimiport and other Smart features"
---

One of DefectDojo’s strengths is that the data model can accommodate many different use\-cases and applications. You’ll likely change your approach as you master the software and discover ways to optimize your workflow.



By default, DefectDojo does not delete any duplicate Findings that are created. Each Finding is considered to be a separate instance of a vulnerability. So in this case, **Duplicate Findings** can be an indicator that a process change is required to your workflow. 




# Step 1: Clean up your excess Duplicates


Fortunately, DefectDojo’s Deduplication settings allow you to mass\-delete duplicates once a certain threshold has been crossed. This feature makes the cleanup process easier. To learn more about this process, see our article on **Finding Deduplication** \<\-link will go here.



# Step 2: Evaluate your Engagements for redundancies


Once you’ve cleaned up your duplicate Findings, it’s a good practice to look at the Product which contained them to see if there’s a clear culprit. You might find that there are Engagements contained within which have a redundant context.



## Duplicate or Reused Engagements


Engagements store one or more Tests for a particular testing context. That context is ultimately up to you to define for yourself, but if you see a few Engagements within your Product which should share the same context, consider combining them into a single engagement.  
​


## Questions to ask when defining Engagement context:


* If I wanted to make a report on this work, would the Engagement contain all of the relevant information I need?
* Are we proactively creating Engagements ahead of time or are they being created ‘ad\-hoc’ by my import process?
* Are we using the right kind of Engagement \- **Interactive** or **CI/CD**?
* What section of the codebase is being worked on by tests: is each repository a separate context or could multiple repositories make up a shared context for testing?
* Who are the stakeholders involved with the Productt, and how will I share results with them?


# Step 3: Check for redundant Tests


If you discover that separate Tests have been created which capture the same testing context, this may be an indicator that these tests can be consolidated into a single Reimport.



DefectDojo has two methods for importing test data to create Findings: **Import** and **Reimport**. Both of these methods are very similar, but the key difference between the two is that **Import** always creates a new Test, while **Reimport** can add new data to an existing Test. It’s also worth noting that **Reimport** does not create duplicate Findings within that Test.



Each time you import new vulnerability reports into DefectDojo, those reports will be stored in a Test object. A Test object can be created by a user ahead of time to hold a future **Import**. If a user wants to import data without specifying a Test destination, a new Test will be created to store the incoming report.



Tests are flexible objects, and although they can only hold one *kind* of report, they can handle multiple instances of that same report through the **Reimport** method. To learn more about Reimport, see our **[article](https://support.defectdojo.com/en/articles/9424972-reimport-recurring-tests)** on this topic.




# When are Duplicate Findings acceptable?


Duplicate Findings are not always indicative of a problem. There are many cases where keeping duplicates is the preferred approach. For example:



* If your team uses and reports on Interactive Engagements. If you want to create a discrete report on a single Test specifically, you would want to know if there’s an occurrence of a Finding that was already uncovered earlier.
* If you have Engagements which are contextually separated (for example, because they cover different repositories) you would want to be able to flag Findings which are occurring in both places.

