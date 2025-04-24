---
title: "Finding Priority Enhancement (Pro)"
description: "How DefectDojo ranks your Findings"
weight: 1
---

Additional Finding filters are available in DefectDojo Pro to more easily triage, filter and prioritize Findings.

* Priority sorts Findings based on the context and importance of the Product they are stored in.
* Risk considers the Product's context, with a greater emphasis on the exploitability of a Finding.

## Finding Priority

In DefectDojo Pro, Priority is a calculated field on Findings that can be used to sort or filter Findings according to Product-level metadata:

- Product's Business Criticality
- Whether the Product has an External Audience
- Whether the Product is Internet Accessible
- The Product's estimated revenue or user records count 

DefectDojo Pro's Finding Priority assigns a numerical rank to each Finding according to this metadata, to provide users with a stronger context on triage and remediation.

![image](images/pro_finding_priority.png)

The range of Priority values is from 0 to 1150.  The higher the number, the more urgency the Finding is to triage or remediate.

Priority numbers can be used with other filters to compare Findings in any context, such as:

* within a single Product, Engagement or Test
* globally in all DefectDojo Products
* between a few specific Products

## How Priority is calculated

Every Active finding will have a Priority calculated.  Inactive or Duplicate Findings will not.

Priority is set based on the following factors:

#### Product-Level

- The assigned Criticality for the Product (if defined)
- The estimated User Records for the Product (if defined)
- The estimated Revenue for the Product (if defined)
- If the Product has External Audience defined
- If the Product has Internet Accessible defined.

All of these metadata fields can be set on the Edit Product form for a given Product.

#### Finding-Level

- Whether or not the Finding has an [EPSS score](/en/working_with_findings/intro_to_findings/#monitor-current-vulnerabilities-using-cves-and-epss-scores-pro-feature), this is automatically kept up to date for Pro customers
- How many Endpoints in the Product are affected by this Finding
- Whether or not a Finding is Under Review

If Product-level metadata is not set, the Priority level will follow the Severity for a given Finding:

- Critical = 90
- High = 70
- Medium = 50
- Low = 30
- Info = 10

Currently, Priority calculation and the underlying formula cannot be adjusted.  These numbers are meant as a reference only - your team's actual priority for remediation may vary from the DefectDojo calculation.

## Finding Risk

![image](images/risk_table.png)

The Risk column on a Findings table is another way to quickly prioritize Findings.  Risk is calculated using a Finding's Priority level, but also factors in a Finding's exploitability to a greater degree.  This is meant as a less granular, more 'executive-level' version of Priority.

The four assignable Risk levels are:

![image](images/pro_risk_levels.png)

A Finding's EPSS / exploitability is much more emphasized in the Risk calculation.  As a result, a Finding can have a both a high priority and a low risk value.

As with Finding Priority, the Risk calculation cannot currently be adjusted.
