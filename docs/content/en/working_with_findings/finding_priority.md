---
title: "⏱️ Finding Priority and Risk (Pro)"
description: "How DefectDojo ranks your Findings"
weight: 1
---

![image](images/pro_finding_priority.png)

Effective risk-based vulnerability management requires an approach that considers
both business context and technical exploitability. Using DefectDojo Pro’s Priority and Risk feature, users can automatically sort Findings into a meaningful context, ensuring
high-impact vulnerabilities can be addressed first.

**Priority** is a calculated numerical rank applied to all Findings in your DefectDojo
instance. It allows you to quickly understand vulnerabilities in context, especially within
large organizations that are overseeing security needs for many Findings and/or
Products.

**Risk** is a 4-level ranking system which factors in a Finding’s exploitability to a greater
degree. This is meant as a less granular, more ’executive-level’ version of Priority.

![image](images/pro_risk_example.png)

Priority and Risk values can be used with other filters to compare Findings in any context, such as:

* within a single Product, Engagement or Test
* globally in all DefectDojo Products
* between a few specific Products

Applying Finding Priority and Risk helps your team respond to the most relevant
vulnerabilities in your organization, and also provides a framework to assist in
compliance with regulatory standards.


Learn more about Priority and Risk with DefectDojo Inc's May 2025 Office Hours:
<iframe width="560" height="315" src="https://www.youtube.com/embed/4SN0BWWsVm4?si=VYUzEGNeijjhoD22" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>


## How Priority & Risk are calculated
The range of Priority values is from 0 to 1150. The higher the number, the more urgency
the Finding is to triage or remediate.

Similar to Severity, Risk is scored from Low -> Medium -> Needs Action -> Urgent.  **Risk** considers Priority fields and may be different from a tool's reported Severity as a result.

![image](images/priority-overview.png)

## Priority Fields: Product-Level

Each Product in DefectDojo has metadata that tracks business criticality and risk
factors. This metadata is used to help calculate Priority and Risk for any associated
Findings.

All of these metadata fields can be set on the **Edit Product** form for a given Product.

![image](images/priority_edit_product.png)

* **Criticality** can be set to any value of None, Very Low, Low, Medium, High, or Very
High. Criticality is a subjective field, so when assigning this field, consider how the
Product compares to other Products in your organization.
* **User Records** is a numerical estimation of user records in a database (or a system
that can access that database).
* **Revenue** is a numerical estimation of annual revenue for the Product. It is not
possible to set a currency type in DefectDojo, so make sure that all of your Revenue
estimations have the same currency denomination. (“50000” could mean $50,000
US Dollars or ¥50,000 Japanese Yen - the denomination does not matter as long as
all of your Products have revenue calculated in the same currency).
* **External Audience** is a true/false value - set this to True if this Product can be
accessed by an external audience. For example, customers, users, or anyone
outside of your organization.
* **Internet Accessible** is a true/false value. If this Product can connect to the open
internet, you should set this value to True.

Priority is a ‘relative’ calculation, which is meant to compare different Products within
your DefectDojo instance. It is ultimately up to your organization to decide how these
filters are set. These values should be as accurate as possible, but the primary goal is
to highlight your key Products so that you can prioritize vulnerabilities according to your
organization’s policies, so these fields do not necessarily need to be set perfectly.

## Priority Fields: Finding-Level

Findings within a Product can have additional metadata which can further adjust the Finding’s Priority and Risk level:

* Whether or not the Finding has an EPSS score, this is automatically added to Findings and kept up to date for Pro users
* How many Endpoints in the Product are affected by this Finding
* Whether or not a Finding is Under Review
* Whether the Finding is in the KEV (Known Exploited Vulnerabilities) database, which is checked by DefectDojo on a regular basis
* The tool-reported Severity of a Finding (Info, Low, Medium, High, Critical)

Currently, Priority calculation and the underlying formula cannot be adjusted. These
numbers are meant as a reference only - your team’s actual priority for remediation
may vary from the DefectDojo calculation.

## Finding Risk Calculation

![image](images/risk_table.png)

The Risk column on a Findings table is another way to quickly prioritize Findings.  Risk is calculated using a Finding's Priority level, but also factors in a Finding's exploitability to a greater degree.  This is meant as a less granular, more 'executive-level' version of Priority.

The four assignable Risk levels are:

![image](images/pro_risk_levels.png)

A Finding's EPSS / exploitability is much more emphasized in the Risk calculation.  As a result, a Finding can have both a high priority and a low risk value.

As with Finding Priority, the Risk calculation cannot currently be adjusted.

## Priority Insights Dashboard

Users can take an executive-level view of Priority and Risk in their environment using
the Priority Insights Dashboard (Metrics > Priority Insights in the sidebar)

![image](images/priority_dashboard.png)

This dashboard can be filtered to include specific Products or date ranges. As with
other Pro dashboards, this dashboard can be exported from DefectDojo as a PDF to
quickly produce a report.

## Setting Priority & Risk for Regulatory Compliance

This is a non-exhaustive list of regulatory standards that specifically require
vulnerability prioritization methods:

* [SOX (Sarbanes-Oxley Act](https://www.sarbanes-oxley-act.com/)) compliance requires revenue-based prioritization for
systems impacting financial data. In DefectDojo, a system’s revenue can be entered
at the Product level.
* [PCI DSS](https://www.pcisecuritystandards.org/standards/pci-dss/) compliance requires prioritization based on risk ratings and criticality to
cardholder data environments. Business Criticality and External Audience can be
set at the Product level, while DefectDojo’s Finding-level EPSS sync supports PCI’s
risk-based approach.
* [NIST SP 800-40](https://csrc.nist.gov/pubs/sp/800/40/r4/final) is a preventative maintenance guide which specifically calls for
vulnerability prioritization based on business impact, product criticality and
internet accessibility factors. All of these can be set at DefectDojo’s Product level.
* [ISO 27001/27002](https://www.iso.org/standard/27001) Control A.12.6.1 compliance requires management of technical
vulnerabilities with Priority based on risk assessment.
* [GDPR Article 32](https://gdpr-info.eu/art-32-gdpr/) requires risk-based security measures - user records and external
audience flags at the Product level can help prioritize systems in your organization
that process personal data.
* [FISMA/FedRAMP](https://help.fedramp.gov/hc/en-us) compliance require continuous monitoring and risk-based vulnerability remediation.