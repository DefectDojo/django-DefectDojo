---
title: "About Our Documentation"
date: 2021-02-02T20:46:29+01:00
draft: false
type: docs

weight: 1

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

1. [Installation](../../open_source/installation/) covers how to install and configure DefectDojo.
2. [New User Checklist](../new_user_checklist) covers how to use DefectDojo to manage vulnerabilities.
3. We support a large amount of [integrations](../../connecting_your_tools/parsers/) to help fit DefectDojo in your DevSecOps program.

### Where to find DefectDojo?

The open-source edition is [available on
GitHub](https://github.com/DefectDojo/django-DefectDojo).

A running example is available on [our demo server](https://demo.defectdojo.org),
using the credentials `admin` / `1Defectdojo@demo#appsec`. Note: The demo
server is refreshed regularly and provisioned with some sample data.

### DefectDojo Pro

DefectDojo Inc. hosts a commercial edition of this software, which includes: 
- additional features, smart features and UI improvements 
- cloud hosting, with regular backups, updates and maintenance
- premium support and implementation guidance

For more information, please visit [defectdojo.com](https://www.defectdojo.com/).

DefectDojo Inc. maintains this documentation to support both the Community and Pro editions of DefectDojo.

Follow DefectDojo Inc. on [LinkedIn](https://www.linkedin.com/company/33245534) for updates.
To get in touch with us, please reach out to info@defectdojo.com
