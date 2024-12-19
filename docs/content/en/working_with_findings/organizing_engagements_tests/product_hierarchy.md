---
title: "Product Hierarchy: Overview"
description: "Understand Product Types, Products, Engagements, Tests and Findings"
---

DefectDojo uses five main data classes to organize your work: **Product Types, Products**, **Engagements**, **Tests**, and **Findings**.



DefectDojo is made to be flexible to conform to your team, rather than making your team conform to the tool. You'll be able to design a robust, adaptable workspace once you understand how these data classes can be used to organize your work.




# **Product Types**


The first category of data you'll need to set up in DefectDojo is a Product Type. Product Types are intended to categorize Products in a specific way. This could be:


* by business domain
* by development team
* by security team

![image](images/Product_Hierarchy_Overview.png)
Product Types can have Role\-Based Access Control rules applied, which limit team members' ability to view and interact with their data (including any underlying Products with Engagement, Test and Finding data). For more information on user roles, see our **Introduction To Roles** article.




## What can a Product Type represent?


* If a particular software project has many distinct deployments or versions, it may be worth creating a single Product Type which covers the scope of the entire project, and having each version exist as individual Products.  
​
* You also might consider using Product Types to represent stages in your software development process: one Product Type for 'In Development', one Product Type for 'In Production', etc.  
​
* Ultimately, it's your decision how you wish to organize your Products, and what you Product Type to represent. Your DefectDojo hierarchy may need to change to fit your security teams' needs.



# **Products**


A **Product** in DefectDojo is intended to represent any project, program, or product that you are currently testing. The Product hosts all of the security work and testing history related to the underlying goal.



![image](images/Product_Hierarchy_Overview_2.png)


* a unique **Name**
* a **Description**
* a product **Type**
* an assigned **SLA Configuration**

Products can be as broad or as specific in scope as you wish. By default, Products are completely separate objects in the hierarchy, but they can be grouped together by **Product Type**.



Products are 'walled\-off' and do not interact with other Products. DefectDojo's Smart Features, such as **Deduplication**, only apply within the context of a single Product.



Like **Product Types**, **Products** can have Role\-Based Access Control rules applied, which limit team members' ability to view and interact with them (as well as any underlying Engagement, Test and Finding data). For more information on user roles, see our **Introduction To Roles** article.




## What can a Product represent?


DefectDojo's concept of a 'Product' will not necessarily correspond 1:1 to what your organization would refer to as a 'Product'. Software development is complex, and security needs can vary greatly even within the scope of a single piece of software.



The following scenarios are good reasons to consider creating a separate DefectDojo Product:


* "**ExampleProduct**" has a Windows version, a Mac version, and a Cloud version
* "**ExampleProduct 1\.0**" uses completely different software components from "**ExampleProduct 2\.0**", and both versions are actively supported by your company.
* The team assigned to work on "**ExampleProduct version A**" is different than the product team assigned to work on "**ExampleProduct version B**", and needs to have different security permissions assigned as a result.


These variations within a single Product can also be handled at the Engagement level. Note that Engagements don't have access control in the way Products and Product Types do. 


# **Engagements**


Once a Product is set up, you can begin creating and scheduling Engagements. Engagements are meant to represent moments in time when testing is taking place, and contain one or more **Tests**. 



Engagements always have:


* a unique **Name**
* target **Start and End dates**
* **Status** (Not Started, In Progress, Cancelled, Completed...)
* an assigned **Testing Lead**
* an associated **Product**

There are two types of Engagement: **Interactive** and **CI/CD**. 


* An **Interactive Engagement** is typically run by an engineer. Interactive Engagements are focused on testing the application while the app is running, using an automated test, human tester, or any activity “interacting” with the application functionality. See [OWASP's definition of IAST](https://owasp.org/www-project-devsecops-guideline/latest/02c-Interactive-Application-Security-Testing#:~:text=Interactive%20Application%20Security%20Testing,interacting%E2%80%9D%20with%20the%20application%20functionality.).
* A **CI/CD Engagement** is for automated integration with a CI/CD pipeline. CI/CD Engagements are meant to import data as an automated action, triggered by a step in the release process.

Engagements can be tracked using DefectDojo's **Calendar** view. 




## What can an Engagement represent?


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



Engagements can be organized however works best for your team. All Engagements nested under a Product can be viewed by the team assigned to work on the Product.



# **Tests**


Tests are a grouping of activities conducted by engineers to attempt to discover flaws in a product.



Tests always have:


* a unique **Test Title**
* a specific **Test Type (**API Test, Nessus Scan, etc)
* an associated test **Environment**
* an associated **Engagement**

Tests can be created in different ways. Scan data can be directly imported to an Engagement, which will then create a new Test containing that data. Tests can also be created in advance without scan data, as part of planning future Engagements.




## **How do Tests interact with each other?**


Tests take your testing data and group it into Findings. Generally, security teams will be running the same testing effort repeatedly, and Tests in DefectDojo allow you to handle this process in an elegant way.



**Previously imported tests can be reimported** \- If you're running the same type of test within the same Engagement context, you can Reimport the test results after each completed scan. DefectDojo will compare the Reimported data to the existing result, and will not create new Findings if duplicates exist in the scan data.



**Tests can be imported separately** \- If you run the same test on a Product within separate Engagements, DefectDojo will still compare the data with previous Tests to find duplicate Findings. This allows you to keep track of previously mitigated or risk\-accepted Findings.



If a Test is added directly to a Product without an Engagement, a generic Engagement will be created automatically to contain the Test. This allows for ad\-hoc data imports.



**Examples of Tests:**


* Burp Scan from Oct. 29, 2015 to Oct. 29, 2015
* Nessus Scan from Oct. 31, 2015 to Oct. 31, 2015
* API Test from Oct. 15, 2015 to Oct. 20, 2015


# **Findings**


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

