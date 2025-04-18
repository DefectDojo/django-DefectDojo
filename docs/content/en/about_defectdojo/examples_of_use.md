---
title: "💡 Common Use-Cases"
description: "Use Cases and examples"
draft: "false"
weight: 2
chapter: true
---

This article is based on DefectDojo Inc's February Office Hours: "Tackling Common-Use Cases".
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=ilRBlfo-wvX5DPVg" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

## Examples of Use-Cases

DefectDojo is designed handle any security implementation: no matter your security team size, IT complexity level, or reporting volume.  These stories are intended as jumping-off points for your own needs, but they're based on real examples from our community and DefectDojo Pro team.

### Large Enterprise: RBAC and Engagements

'BigCorp' is a large multinational enterprise, with a CISO and a centralized IC security group that includes AppSec. 

Security at BICORP is highly centralized.  Certain things are delegated out to BISOs (Business Information Security Officers).

The key concerns for BigCorp are:

- Set and maintain a consistent testing method across all business units in the organization
- Meet compliance requirements and avoid regulatory issues

#### Testing Model

BigCorp handles security data from many sources:

- CI/CD jobs that run SAST, SCA and Secret scanning tools automatically
- Third-party Pen testing for certain Products
- PCI compliance auditing for certain Products

Each of these report categories can be handled by a separate Engagement, with a separate Test for each kind of test in DefectDojo.

![image](images/example_product_hierarchy_bigcorp.png)

- If a Product has a CI/CD pipeline, all of the results from that pipeline can be continuously imported into a single open-ended Engagement. Each tool used will create a separate Test within the 'CI/CD' Engagement, which can be continuously updated with new data.
- Each Pen Test effort can have a separate Engagement created to contain all of the results: e.g. 'Q1 Pen Test 2024', 'Q2 Pen Test 2024', etc.
- BigCorp will likely want to run their own mock PCI Audit so that they're prepared for the real thing when it happens. The results of those audits can also be stored as a separate Engagement.

#### RBAC Model

- Each BISO has Reader access assigned for each business unit (Product Type) that they're in charge of.
- Each Product Owner has Writer access for the Product that they're in charge of.  Within their Product, these Product Owners can interact with DefectDojo - they can keep notes, set up pipelines, create Risk Acceptances or use other features.
- Developers at BigCorp have no access to DefectDojo at all, and they don't need it - the Product Owner can push Jira tickets directly from DefectDojo which contain all of the relevant vulnerability information.  The developers are already using Jira, so they don't have to track remediation any differently than a different development task.

### Embedded Systems: Version-Controlled Reporting

Cyber Robotics is a company that sells manufacturing hardware that comes with embedded software systems.  They have a Chief Product Officer that oversees both their product and cybersecurity as a whole.

Though they have less diverse security information to manage than BigCorp, it's still essential for them to properly contextualize their security information so that they can proactively respond to any significant Findings.

Key concerns for Cyber Robotics:

- They have a limited product line but **many** versions of each product that they need to properly catalog.
- Maintenance for their products is complex and costs are high, so unnecessary work needs to be avoided.

#### Testing Model

Cyber Robotics has a standardized testing process for all of their embedded systems: 

- CI/CD, SAST, and SCA tests are run.
- Security Control Reviews
- Network Scans
- Third Party Code Review

However, because each version of their software is isolated, they'll inevitably have a lot of data to organize, much of which is only useful in a single context (the particular version of the software they're running).

Cyber Robotics can solve this problem by using Product Types here to represent a single product line, and individual Products for each separate version.  This will allow them to drill down to determine which Products are associated with a single vulnerability.

![image](images/example_product_hierarchy_robotics.png)

Assigning software versions to Products, rather than Engagements allows Cyber Robotics to limit access to a particular software version, if necessary.  Field technicians and Support staff can be granted access to a single version of the software without having to give them access to the entire product line.

#### RBAC Model

The AppSec team here has Global Roles assigned that govern their level of interaction.

- The Chief Product Officer has Global Reader access to DefectDojo, as with the CISO in BigCorp.
- Individual Product Owners have Global Reader access to any Product in DefectDojo, as well as Writer access to the Product that they own.

On the Support side:

- Support Personnel are temporarily granted Reader access to specific Products that they're assigned to maintain, but they do not have access to all DefectDojo data.

### Dynamic IT environments and microservices: Cloud Services company

Kate's Cloud Service operates a rapidly changing environment that uses Kubernetes, microservices, and automation.  Kate's Cloud Service has a VP of Cloud that oversees Cloud Security issues.  They also have a CISO who manages the software development on offer, but for this example we will focus specifically on their Cloud security concerns.

Kate's Cloud Service has fully automated all of their reporting, and ingests data into DefectDojo as soon as reports are produced.

Key Concerns for Kate's Cloud Service:

- managing multi-tenant cloud security, preventing cross-customer interaction while enabling shared service delivery
- handling rapid changes in their cloud environment

#### Tagging Shared Services

Because Kate's model contains many shared services that can impact other Products, the team Tags the results to indicate which cloud offerings rely on those services.  This allows any issues with shared services to be traced back to the relevant teams, and reports in DefectDojo.  Each of these Shared Services are in a single Product Type that separates them from the main Cloud offerings.

![image](images/example_product_hierarchy_microservices.png)

Because the company is rapidly growing, with frequently changing tech leads, Kate can use Tags to track which tech lead is currently responsible for each cloud product, avoiding the need for constant manual updates to their DefectDojo system.  These Tech Lead associations are tracked by a service that's external to DefectDojo and can govern the import pipelines or call the DefectDojo API.

#### RBAC Model

On the Security/Compliance side:

- The Product Security Team that owns DefectDojo has admin access to the entire system.
- Analysts working for the VP of Cloud are granted read-only access across the system, allowing them to generate the necessary reports and metrics for the VP to assess the security of various cloud offerings.

On the development side:

- Tech Leads for each specific cloud product (e.g., compute, storage, shared services) have **Maintainer access** to their assigned Product, to triage the security results related to their specific cloud product offering. They can review Findings and take action within their Product, and can also reorganize their Finding data significantly.
- Developers working on specific Products are given **Writer Access** to the Product they're working on, enabling them to comment on Findings, request Peer Reviews, and create Risk Acceptances.

### Onboarding New Acquisitions: SaaSy Software

SaaSy software is a rapidly growing firm which frequently acquires other software companies.  Every time a new company is acquired, the Director Of Quality engineering and the AppSec team is suddenly in charge of many new code repos, developers and processes.  Their DefectDojo model ensures that they can get up to speed as soon as possible.

Key Concerns for SaaSy Software:

- avoiding public security issues while maintaining compliance programs (such as SOC2)
- ability to confidently onboard tools and processes from new products
- ability to report and categorize vulnerabilities on both in-production and in-development branches

#### Testing Model

Testing at SaaSy is focused on broad strokes rather than standardized tool use, since each acquisition comes with their own tools and processes for AppSec.  SaaSy needs to perform both internal assessments (CI/CD, DAST, Container scans, Threat Modeling) and external assessments (3rd party Pen Tests, Compliance audits.)

To assist with onboarding new applications, SaaSy software has a standard approach to their data model.  Each time SaaSy onboards a new application, they create a new Product Type for that app, and create sub-products for the repositories that make it up; (Front-End, Backend API, etc.)

![image](images/example_product_hierarchy_saas.png)

Each of these Products is further subdivided into Engagements, one for the main branch and one for each branch of development.  Tests within these Engagements are used to categorize the testing efforts.  Development branches have separate Tests which store the results of CI/CD and SCA scans.  The Main branch has those as well, but also adds Tests which store Manual Code Review and Threat Model reports.

All of these Tests are open-ended and can be updated on a regular basis using Reimport.  Deduplication is only handled at the Engagement level, which prevents Findings in one Code branch from closing Findings in another.

By applying this model consistently, SaaSy has a model that they can apply to any new software acquisition, and the AppSec team can quickly begin monitoring the data to ensure compliance.

#### RBAC Model

On the Security/Compliance side:

- The AppSec team at SaaSy software owns DefectDojo and has full admin access to the software.
- QE and Compliance teams have read-only access to the entire system, to pull reports and dive into data if required.

On the development side:

- Each Product Owner has Writer access to the Product they own in DefectDojo, which allows them to write Risk Acceptances and view metrics for the Product.
- Developers have read-only access to each Product they work on.  They can Request Peer Reviews on Findings or issues they are trying to remediate.
