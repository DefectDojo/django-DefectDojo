---
title: "DefectDojo\'s Documentation"
date: 2021-02-02T20:46:29+01:00
draft: false
type: docs

cascade:
- type: "blog"
  # set to false to include a blog section in the section nav along with docs
  toc_root: true
  _target:
    path: "/blog/**"
- type: "docs"
  _target:
    path: "/**"
---

![image](images/dashboard.png)

### What is DefectDojo?

DefectDojo is a DevSecOps platform. DefectDojo streamlines DevSecOps by serving as an aggregator and single pane of glass for your security tools. DefectDojo has smart features to enhance and tune the results from your security tools including the ability to merge findings, remember false positives, and distill duplicates. DefectDojo also integrates with JIRA, provides metrics / reports, and can also be used for traditional pen test management.

### What does DefectDojo do?

While automation and efficiency are the ultimate end goals, DefectDojo is
a bug tracker at its core for vulnerabilities. Taking advantage of DefectDojo's
Product:Engagement model, enables traceability among multiple projects
/ test cycles, and allows for fine-grained reporting.

### How does DefectDojo work?

1. [Getting started]({{< ref "/getting_started" >}}) covers how to install and configure DefectDojo.
2. [Usage]({{< ref "/usage" >}}) covers how to use DefectDojo to manage vulnerabilities.
3. We support a large amount of [integrations]({{< ref "/integrations" >}}) to help fit DefectDojo in your DevSecOps program.

### Where to find DefectDojo?

The open-source edition is [available on
GitHub](https://github.com/DefectDojo/django-DefectDojo).

A running example is available on [our demo server](https://demo.defectdojo.org),
using the credentials `admin` / `1Defectdojo@demo#appsec`. Note: The demo
server is refreshed regularly and provisioned with some sample data.

### DefectDojo Pro and Enterprise

DefectDojo Inc. hosts a commercial edition of this software, which includes: 
- additional features, smart features and UI improvements 
- cloud hosting, with regular backups, updates and maintenance
- premium support and implementation guidance

For more information, please visit [defectdojo.com](https://www.defectdojo.com/).

DefectDojo Inc. also maintains an updated Knowledge Base at [https://support.defectdojo.com](https://support.defectdojo.com/en/). The Knowledge Base is written to support DefectDojo's Pro and Enterprise releases, but the tutorials and guides may also be applied to the open-source edition.

Follow DefectDojo Inc. on [LinkedIn](https://www.linkedin.com/company/33245534) for updates.
To get in touch with us, please reach out to info@defectdojo.com
