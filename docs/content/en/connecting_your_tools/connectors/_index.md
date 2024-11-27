---
title: "Set Up API Connectors"
description: "Seamlessly connect DefectDojo to your security tools suite"
summary: ""
date: 2023-09-07T16:06:50+02:00
lastmod: 2023-09-07T16:06:50+02:00
draft: false
weight: 2
chapter: true
sidebar:
  collapsed: true
seo:
  title: "" # custom title (optional)
  description: "" # custom description (recommended)
  canonical: "" # custom canonical URL (optional)
  robots: "" # custom robot tags (optional)
pro-feature: true
---


DefectDojo allows users to build sophisticated API integrations, and gives users full control over how their vulnerability data is organized. 



But everyone needs a starting point, and that's where Connectors come in. Connectors are designed to get your security tools connected and importing data to DefectDojo as quickly as possible.



We currently support Connectors for the following tools, with more on the way:


* **AWS Security Hub**
* **BurpSuite**
* **Checkmarx ONE**
* **Dependency\-Track**
* **Probely**
* **Semgrep**
* **SonarQube**
* **Snyk**
* **Tenable**

These Connectors provide an API\-speed integration with DefectDojo, and can be used to automatically ingest and organize vulnerability data from the tool.




# Connectors Quick\-Start


If you're using DefectDojo's **Auto\-Map** settings, you can have your first Connector up and running in no time.


1. Set up a [Connector](https://support.defectdojo.com/en/articles/9056787-add-or-edit-a-connector) from a supported tool.
2. [Discover](https://support.defectdojo.com/en/articles/9056822-discover-operations) your tool's data hierarchy.
3. [Sync](https://support.defectdojo.com/en/articles/9124820-sync-operations) the vulnerabilities found with your tool into DefectDojo.

That's all, really! And remember, even if you create your Connector the 'easy' way, you can easily change the way things are set up later, without losing any of your work.




# How Connectors Work


As long as you have the API key from the tool you're trying to connect, a connector can be added in just a few minutes. Once the connection is working, DefectDojo will **Discover** your tool's environment to see how you're organizing your scan data.



Let's say you have a BurpSuite tool, which is set up to scan five different repositories for vulnerabilities. Your Connector will take note of this organizational structure and set up **Records** to help you translate those separate repositories into DefectDojo's Product / Engagement / Test hierarchy. If you have **'Auto\-Map Records'** enabled, DefectDojo will learn and copy that structure automatically.




![image](images/_index.png)

Once your **Record** mappings are set up, DefectDojo will start importing scan data on a regular basis. You'll be kept up to date on any new vulnerabilities detected by the tool, and you can start working with existing vulnerabilities immediately, using DefectDojo's **Findings** system.



When you're ready to add more tools to DefectDojo, you can easily rearrange your import mappings to something else. Multiple tools can be set up to import vulnerabilities to the same destination, and you can always reorganize your setup for a better fit without losing any work.




# My Connector isn't supported


Fortunately, DefectDojo can still handle manual import for a wide range of security tools. Please see our [Supported Tool List](https://support.defectdojo.com/en/articles/9641650-supported-tool-list), as well as our guide to Importing data.




# **Next Steps**


* Check out the Connectors page by switching to DefectDojo's [Beta UI](https://support.defectdojo.com/en/articles/9056775-switching-to-the-beta-ui).
* Follow our guide to [create your first Connector](https://support.defectdojo.com/en/articles/9056787-add-or-edit-a-connector).
* Check out the process of [Discovering \& Mapping](https://support.defectdojo.com/en/articles/9056822-discovery-records) your security tools and see how they can be configured to import data.
