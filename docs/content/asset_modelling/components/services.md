---
title: "Services"
description: "Tracking Microservices"
weight: 1
---

## What is a Service?

Services (short for Microservices) are an optional feature within Assets that provides additional context for where Findings originate within an Asset. They help to isolate Findings to a particular component of an Asset, rather than the entire Asset as a whole, providing clarity and reporting precision in environments with complex architectures.

Services are useful when you need to further segment any results that come in from a Test, or if you expect to have multiple instances of the same Finding within a Reimport pipeline that you don’t want to deduplicate. Some scan tools might create separate Findings for each file location, and if you prefer to keep those instances of a Finding as separate Findings, services might be a useful way to label those different locations.

## Services in Pro

Services are available in the Pro version, but are largely superseded by the ability to establish parent-child relationships between Assets. Services achieve the same outcome, and may still be useful when restructuring Assets is not feasible or when scan-level deduplication scoping is required without altering the Asset hierarchy, but they remove context. For example, business criticality, revenue, and personnel can be attributed to Assets but not Services. As such, Services are primarily useful in the context of OS DefectDojo.

## How do I specify a Service? 

The option to specify a Service is available on the Import Scan or Reimport forms within the Optional Fields dropdown menu. Thereafter, deduplication is scoped to Tests that share the same Service value.

Importantly, Services are case-sensitive. If the Service of the initial import was identified as “Service 1” (uppercase S) and you reimport a scan that has resolved all previous issues but identify the Service as “service 1” (lowercase S), deduplication will not apply to the intended Service.

## How do Services function? 

Services function by allowing you to specify which prior Tests deduplication rules will apply to upon Reimport. 

If, for example, you import one scan and set Service as “Service 1,” then reimport a second scan and set Service as “Service 2,” deduplication will not apply between those two scans because the Service is different.

Any subsequent reimports will only deduplicate prior results from the first scan if Service has been set as “Service 1,” and will only deduplicate prior results from the second scan if Service has been set as “Service 2.” Essentially, if Service is different between two versions of a reimported scan, they will be treated as different Findings, even if the scans themselves are identical. 

In this example, if, upon reimport, Service is not set as either Service 1 or Service 2, and is instead left blank, then deduplication will not apply to either the first or second scan, and only Findings without a Service will be closed.

## How should Services be used?

In practice, Services are most useful when:

* A single Asset contains multiple independently deployed components.
* Different teams own different parts of the same Asset.
* Security testing is performed against individual services (for example, scanning a specific API or microservice).
