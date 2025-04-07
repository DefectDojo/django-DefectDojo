---
title: "About Our Documentation"
date: 2021-02-02T20:46:29+01:00
draft: false
type: docs
weight: 1
---

![image](images/dashboard.png)


<span style="background-color:rgba(242, 86, 29, 0.3)">DefectDojo Inc. and open-source contributors maintain this documentation to support both the Community and Pro editions of DefectDojo.</span>

## What is DefectDojo?

DefectDojo is a DevSecOps platform. DefectDojo streamlines DevSecOps by serving as an aggregator and single pane of glass for your security tools.

DefectDojo has smart features to enhance and tune the results from your security tools including the ability to merge findings, remember false positives, and distill duplicates. 

DefectDojo also integrates with JIRA, provides metrics / reports, and can also be used for traditional pen test management.

### What does DefectDojo do?

Whether you're a one-person security team for a small organization, or a CISO overseeing a large amount of software projects, DefectDojo allows you to organize your security work, and easily report your organization's security posture to other stakeholders.

While security process automation and integrated development pipelines are the ultimate end goals of DefectDojo, this software is a bug tracker at its core for security vulnerabilities, which is meant to ingest, organize and standardize reports from many security tools. 

DefectDojo's Product:Engagement model enables allows you to take inventory of your development environment and immediately place new security Findings in context.

- Track and report on vulnerabilities and test results across repositories and development branches, using CI/CD integration
- Ingest Pen tester reports and capture point-in-time snapshots of your security profile
- Create and track Risk Acceptances for security vulnerabilities
- Set and enforce SLAs to reflect your organization's policies for vulnerability remediation
- Filter out redundant data using DefectDojo's deduplication algorithm

---
Here are some examples of ways DefectDojo can be implemented, with DefectDojo co-founder and CTO Matt Tesauro:
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---


### How does DefectDojo work?

Whether you're a Pro or an Open-Source user, we have many resources that can help you get started with DefectDojo.

- Our [New User Checklist](../new_user_checklist) covers the fundamentals of setting up your DefectDojo environment and setting up your import, triage and reporting workflows.

- We support a large amount of [security tool integrations](/en/connecting_your_tools/parsers/) to help fit DefectDojo in your DevSecOps program.

- Our team maintains a [YouTube Channel](https://www.youtube.com/@defectdojo) which hosts tutorials, archived Office Hours events and other content. New subscribers are always welcome!

## Open-Source DefectDojo

The Open-Source edition of DefectDojo is [available on GitHub](https://github.com/DefectDojo/django-DefectDojo).

### Installation Guides

There are a few supported ways to install DefectDojo's Open Source edition:

- [Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) is the easiest method to install the core program and services required to run DefectDojo.
- [Kubernetes](https://github.com/DefectDojo/django-DefectDojo/blob/dev/readme-docs/KUBERNETES.md) is not fully supported at the Open-Source level, but this guide can be referenced and used as a **starting point** to integrate DefectDojo into Kubernetes architecture.

Other guides for working with an Open-Source install:
- [Architecture](/en/open_source/installation/architecture/) gives you an overview of each service and component used by DefectDojo.
- [Running In Production](/en/open_source/installation/running-in-production/) provides system requirements, performance tweaks and maintenance processes for running DefectDojo on a production server.  Note that this guide strictly covers Docker Compose installs, not Kubernetes.

If you run into trouble with an Open Source install, we highly recommend asking questions on the [OWASP Slack](https://owasp.org/slack/invite). Our community members are active on the **# defectdojo** channel and can help you with issues you’re facing.

### Online Demo

A running example of DefectDojo (Open-Source Edition) is available on [our demo server](https://demo.defectdojo.org), using the credentials `admin` / `1Defectdojo@demo#appsec`. The demo server is refreshed regularly and provisioned with some sample data.

## 🟧 DefectDojo Pro Edition

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

DefectDojo Inc. hosts a commercial edition of this software, which includes:

- [additional features](../pro_features), smart features and UI improvements 
- cloud hosting, with regular backups, updates and maintenance
- premium support and implementation guidance

For more information, check out our Pricing page at [defectdojo.com](https://defectdojo.com/pricing).  After filling out a quick survey to assess your organization's needs we'll provide you with a custom quote for DefectDojo.

DefectDojo Pro edition is available as a cloud-hosted SaaS offering but is also available for installation on-premises.

### Connect With Us

* To get in touch with our team, you can always reach out to **info@defectdojo.com**.
* Follow DefectDojo Inc. on [LinkedIn](https://www.linkedin.com/company/33245534) for company updates.
* DefectDojo hosts online presentations for AppSec professionals that can be accessed live or on demand - check us out on our [Events page](https://defectdojo.com/events). Many of these are also available on our [YouTube Channel](https://www.youtube.com/@defectdojo).
