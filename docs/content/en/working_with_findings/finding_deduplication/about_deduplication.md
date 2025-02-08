---
title: "About Deduplication"
description: "Deduplication fundamentals and key concepts"
weight: 1
---

DefectDojo is designed to ingest bulk reports from tools, creating one or more Findings based on the content of the report. When using DefectDojo, you’ll most likely be ingesting reports from the same tool on a regular basis, which means that duplicate Findings are highly likely. 

This is where Deduplication comes in, a Smart feature which you can set up to automatically manage duplicate Findings.

## How DefectDojo handles duplicates

1. First, you import **Test 1\.** Your report contains a vulnerability which is recorded as Finding A.
2. **Later, you import Test 2 which contains the same vulnerability. This will be recorded as Finding B, and Finding B will be marked as a duplicate of Finding A.**
3. Later still, you import **Test 3** which also contains that vulnerability. This will be recorded as Finding C, which will be marked as a duplicate of Finding A.

By creating and marking Duplicates in this way, DefectDojo ensures that all the work for the ‘original’ vulnerability is centralized on the original Finding page, without creating separate contexts, or giving your team the impression that there are multiple separate vulnerabilities which need to be addressed.

By default, these Tests would need to be nested under the same Product for Deduplication to be applied. If you wish, you can further limit the Deduplication scope to a single Engagement.

Duplicate Findings are set as Inactive by default. This does not mean the Duplicate Finding itself is Inactive. Rather, this is so that your team only has a single active Finding to work on and remediate, with the implication being that once the original Finding is Mitigated, the Duplicates will also be Mitigated.

## Deduplication vs Reimport

Deduplication and Reimport are similar processes but they have a key difference:

* When you Reimport to a Test, the Reimport process looks at incoming Findings, **filters and** **discards any matches**. Those matches will never be created as Findings or Finding Duplicates.
* Deduplication is applied 'passively' on Findings that have already been created. It will identify duplicates in scope and **label them**, but it will not delete or discard the Finding unless 'Delete Deduplicate Findings' is enabled.
* The 'reimport' action of discarding a Finding always happens before deduplication; DefectDojo **cannot deduplicate Findings that are never created** as a result of Reimport's filtering.

## When are duplicates appropriate?

Duplicates are useful when you’re dealing with shared, but discrete Testing contexts. For example, if your Product is uploading Test results for two different repositories, which need to be compared, it’s useful to know which vulnerabilities are shared across those repositories.

However, if DefectDojo is creating excess duplicates, this can also be a sign that you need to adjust your pipelines or import processes. 

## What do my duplicates indicate?

* **The same vulnerability, but found in a different context:** this is the appropriate way to use Duplicate Findings. If you have many components which are affected by the same vulnerability, you would likely want to know which components are affected to understand the scope of the problem.  
​
* **The same vulnerability, found in the same context**: better options exist for this case. If the Duplicate Finding does not give you any new context on the vulnerability, or if you find yourself frequently ignoring or deleting your duplicate Findings, this is a sign that your process can be improved. For example, Reimport allows you to effectively manage incoming reports from a CI/CD pipeline. Rather than create a completely new Finding object for each duplicate, Reimport will make a note of the incoming duplicate without creating the Duplicate Finding at all.
