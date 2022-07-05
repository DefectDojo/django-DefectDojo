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

DefectDojo is a security tool that automates application
security vulnerability management. DefectDojo streamlines
the application security testing process by offering features such as
importing third party security findings, merging and de-duping,
integration with Jira, templating, report generation and security
metrics.

### What does DefectDojo do?

While traceability and metrics are the ultimate end goal, DefectDojo is
a bug tracker at its core. Taking advantage of DefectDojo\'s
Product:Engagement model, enables traceability among multiple projects
and test cycles, and allows for fine-grained reporting.

### How does DefectDojo work?

1. [Getting started]({{< ref "/getting_started" >}}) will tell you how to install and configure DefectDojo.
2. [Usage]({{< ref "/usage" >}}) shows how to use DefectDojo to manage vulnerabilities.
3. A lot of [integrations]({{< ref "/integrations" >}}) help to fit DefectDojo in your environment.
4. [Contributing]({{< ref "/contributing" >}}) gives insights how you can help to make DefectDojo even better.

### Where to find DefectDojo?

The code is open source, and [available on
GitHub](https://github.com/DefectDojo/django-DefectDojo).

A running example is available on [the demo server](https://demo.defectdojo.org),
using the credentials `admin` / `defectdojo@demo#appsec`. Note: The demo
server is refreshed regularly and provisioned with some sample data.

You can also find videos of demos on [our YouTube channel](https://www.youtube.com/channel/UC3WVGA1vSO0IV-8cDxdqoPQ).
