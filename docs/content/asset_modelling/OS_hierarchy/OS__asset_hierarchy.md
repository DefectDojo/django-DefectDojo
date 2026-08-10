---
title: "Asset Hierarchy: Overview"
description: "Understand Organizations, Assets, Engagements, Tests and Findings"
weight: 1
audience: opensource
aliases:
  - /en/working_with_findings/organizing_engagements_tests/product_hierarchy
  - /asset_modelling/os_hierarchy/product_hierarchy/
  - /en/asset_modelling/os_hierarchy/product_hierarchy/
---
DefectDojo uses five main data classes to organize your work: **Organizations, Assets**, **Engagements**, **Tests**, and **Findings**.

DefectDojo is made to be flexible to conform to your team, rather than making your team conform to the tool. You'll be able to design a robust, adaptable workspace once you understand how these data classes can be used to organize your work.

### Asset Hierarchy Diagram
![image](images/Asset_Hierarchy_Full.png)


## **Organizations**

The first category of data you'll need to set up in DefectDojo is an Organization. Organizations are intended to categorize Assets in a specific way. This could be:

* by business domain
* by development team
* by security team

![image](images/Asset_Hierarchy_Overview.png)
*Assets are grouped and nested underneath their Organization.*

Organizations can have Role\-Based Access Control rules applied, which limit team members' ability to view and interact with their data (including any underlying Assets with Engagement, Test and Finding data). For more information on user roles, see our **Introduction To Roles** article.

#### What can an Organization represent?

* If a particular software project has many distinct deployments or versions, it may be worth creating a single Organization which covers the scope of the entire project, and having each version exist as individual Assets.
​
* You also might consider using Organizations to represent stages in your software development process: one Organization for 'In Development', one Organization for 'In Production', etc.
​
* Ultimately, it's your decision how you wish to organize your Assets, and what you want your Organizations to represent. Your DefectDojo hierarchy may need to change to fit your security teams' needs.

## **Assets**

An **Asset** in DefectDojo is intended to represent any project, program, or application that you are currently testing. The Asset hosts all of the security work and testing history related to the underlying goal.

![image](images/Asset_Hierarchy_Overview_2.png)

* a unique **Name**
* a **Description**
* an **Organization**
* an assigned **SLA Configuration**

Assets can be as broad or as specific in scope as you wish. By default, Assets are completely separate objects in the hierarchy, but they can be grouped together by **Organization**.

Assets are 'walled\-off' and do not interact with other Assets. DefectDojo's Smart Features, such as **Deduplication**, only apply within the context of a single Asset.

Like **Organizations**, **Assets** can have Role\-Based Access Control rules applied, which limit team members' ability to view and interact with them (as well as any underlying Engagement, Test and Finding data). For more information on user roles, see our **Introduction To Roles** article.

#### What can an Asset represent?

DefectDojo's concept of an 'Asset' will not necessarily correspond 1:1 to what your organization would refer to as a 'Product'. Software development is complex, and security needs can vary greatly even within the scope of a single piece of software.

The following scenarios are good reasons to consider creating a separate DefectDojo Asset:

* "**ExampleAsset**" has a Windows version, a Mac version, and a Cloud version
* "**ExampleAsset 1\.0**" uses completely different software components from "**ExampleAsset 2\.0**", and both versions are actively supported by your company.
* The team assigned to work on "**ExampleAsset version A**" is different than the Asset team assigned to work on "**ExampleAsset version B**", and needs to have different security permissions assigned as a result.

These variations within a single Asset can also be handled at the Engagement level. Note that Engagements don't have access control in the way Assets and Organizations do.

## **Engagements**

Once an Asset is set up, you can begin creating and scheduling Engagements. Engagements are meant to represent moments in time when testing is taking place, and contain one or more **Tests**.

Engagements always have:

* a unique **Name**
* target **Start and End dates**
* **Status** (Not Started, In Progress, Cancelled, Completed...)
* an assigned **Testing Lead**
* an associated **Asset**

There are two types of Engagement: **Interactive** and **CI/CD**.

* An **Interactive Engagement** is typically run by an engineer. Interactive Engagements are focused on testing the application while the app is running, using an automated test, human tester, or any activity “interacting” with the application functionality. See [OWASP's definition of IAST](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* A **CI/CD Engagement** is for automated integration with a CI/CD pipeline. CI/CD Engagements are meant to import data as an automated action, triggered by a step in the release process.

Engagements can be tracked using DefectDojo's **Calendar** view.

#### What can an Engagement represent?

Engagements are meant to represent groups of related testing efforts. How you wish to group your testing efforts depends on your approach.

If you have a planned testing effort scheduled, an Engagement offers you a place to store all of the related results. Here's an example of this kind of Engagement:

#### **Engagement:** ExampleSoftware 1\.5\.2 \- Interactive Testing Effort

*In this example, a security team runs multiple tests on the same day as part of a software release.*

* **Test:** Nessus Scan Results (March 12\)
* **Test:** NPM Scan Audit Results (March 12\)
* **Test:** Snyk Scan Results (March 12\)
​
You can also organize CI/CD Test results within an Engagement. These kinds of Engagements are 'Open\-Ended' meaning that they don't have a date, and will instead add additional data each time the associated CI/CD actions are run.

#### Engagement: ExampleSoftware CI/CD Testing

*In this example, multiple CI/CD scans are automatically imported as Tests every time a new software release is created.*

* Test: 1\.5\.2 Scan Results (March 12\)
* Test: 1\.5\.1 Scan Results (March 3\)
* Test: 1\.5\.0 Scan Results (February 14\)

Engagements can be organized however works best for your team. All Engagements nested under an Asset can be viewed by the team assigned to work on the Asset.

## **Tests**

Tests are a grouping of activities conducted by engineers to attempt to discover flaws in an Asset.

Tests always have:

* a unique **Test Title**
* a specific **Test Type** (API Test, Nessus Scan, etc)
* an associated test **Environment**
* an associated **Engagement**

Tests can be created in different ways.  Tests can be automatically created when scan data is imported directly into an Engagement, resulting in a new Test containing the scan data. Tests can also be created in anticipation of planning future engagements, or for manually entered security findings requiring tracking and remediation.

### **Test Types**

DefectDojo supports two categories of Test Types:

1. **Parser-based Test Types**: These correspond to specific security scanners that produce output in formats like XML, JSON, or CSV. When importing scan results, DefectDojo uses specialized parsers to convert the scanner output into Findings.

2. **Non-parser Test Types**: These are used for manually created Findings not imported from scan files.  These Test Types use the [Generic Findings Import](/supported_tools/parsers/generic_findings_import/) method to render Findings and metadata.

The following Test Types appear in the "Scan Type" dropdown when creating a new test.
   * API Test
   * Static Check
   * Pen Test
   * Web Application Test
   * Security Research
   * Threat Modeling
   * Manual Code Review

Non-parser Test Types should be used when you need to manually create findings that require remediation but don't originate from automated scanner output.

#### **Parser-based Test Types**

Parser-based test types can be categorized by how their test type name is determined:

- **Fixed Test Type Names**: The test type name is predefined and known before import (e.g., "ZAP Scan", "Nessus Scan").

- **Report-Defined Test Type Names**: The test type name is extracted from the scan report content at import time.

Examples include:
  - **Generic Findings Import**: Creates test types based on the `type` field in JSON reports
  - **SARIF**: Creates test types based on tool names in the SARIF report (e.g., "Dockle Scan (SARIF)")
  - **OpenReports**: Creates separate test types per source found in the report

**Report-Defined Test Type Naming Rules:**
- If the report's `type` field equals the scan type → uses scan type directly (e.g., "Generic Findings Import")
- If the report's `type` field differs → creates "{type} Scan ({scan_type})" format (e.g., "Tool1 Scan (Generic Findings Import)")
- If the report's `type` field already ends with the " ({scan_type})" suffix → uses it verbatim, so the suffix is never doubled (e.g., "Tool1 (Generic Findings Import)" stays "Tool1 (Generic Findings Import)")
- If no `type` field is provided → uses scan type directly

**Important Considerations:**
- Report-defined test types are automatically created when a new type is detected during import or reimport.
- For reimports, the test type name must match exactly - mismatches will raise a validation error
- Deduplication settings (`HASHCODE_FIELDS_PER_SCANNER`) use test type names as keys, so report-defined names must be configured accordingly if you want custom deduplication behavior

#### **How do Tests interact with each other?**

Tests take your testing data and group it into Findings. Generally, security teams will be running the same testing effort repeatedly, and Tests in DefectDojo allow you to handle this process in an elegant way.

**Previously imported tests can be reimported** \- If you're running the same type of test within the same Engagement context, you can Reimport the test results after each completed scan. DefectDojo will compare the Reimported data to the existing result, and will not create new Findings if duplicates exist in the scan data.

**Tests can be imported separately** \- If you run the same test on an Asset within separate Engagements, DefectDojo will still compare the data with previous Tests to find duplicate Findings. This allows you to keep track of previously mitigated or risk\-accepted Findings.

If a Test is added directly to an Asset without an Engagement, a generic Engagement will be created automatically to contain the Test. This allows for ad\-hoc data imports.

**Examples of Tests:**

* Burp Scan from Oct. 29, 2015 to Oct. 29, 2015
* Nessus Scan from Oct. 31, 2015 to Oct. 31, 2015
* API Test from Oct. 15, 2015 to Oct. 20, 2015

## **Findings**

Once data has been added uploaded to a Test, the results of that data will be listed in the Test as individual **Findings** for review.

A finding represents a specific flaw discovered while testing.

Findings always have:

* a unique **Finding Name**
* the **Date** they were uncovered
* multiple associated **Statuses**, such as Active, Verified or False Positive
* an associated **Test**
* a **Severity** level: Critical, High, Medium, Low, and Informational (Info).

Findings can be added through a data import, but they can also be added manually to a Test.

**Examples of Findings:**

* OpenSSL ‘ChangeCipherSpec’ MiTM Potential Vulnerability
* Web Application Potentially Vulnerable to Clickjacking
* Web Browser XSS Protection Not Enabled

## **Endpoints**

Scan data generally will contain references to the hosts or endpoints affected by a given Finding.  DefectDojo automatically aggregates Findings per-endpoint, so you can use the Endpoint view to look at all Findings that affect a given Endpoint or Hostname.

Examples:
-   https://www.example.com
-   https://www.example.com:8080/products
-   192.168.0.36
