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

## About DefectDojo

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

Proprietary editions that include [additional features](https://documentation.defectdojo.com/proprietary_plugins/) and support can be purchased through [defectdojo.com](https://www.defectdojo.com/).

The open-source edition is [available on
GitHub](https://github.com/DefectDojo/django-DefectDojo).

A running example is available on [our demo server](https://demo.defectdojo.org),
using the credentials `admin` / `defectdojo@demo#appsec`. Note: The demo
server is refreshed regularly and provisioned with some sample data.

Follow us on [LinkedIn](https://www.linkedin.com/company/33245534) for updates.
To get in touch with us, please reach out to info@defectdojo.com

