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

DefectDojo is a Developer Security Operations (DevSecOps) platform. DefectDojo streamlines DevSecOps by serving as an automatic aggregator for your suite of security tools, allowing you to easily organize your security work and report your organization’s security posture to other stakeholders.

While security process automation and integrated development pipelines are the end goals of DefectDojo, at its core this software is a bug tracker for security vulnerabilities, which is meant to ingest, organize and standardize reports from many security tools.

### What does DefectDojo do?

DefectDojo has smart features to enhance and tune the results from your security tools, including the ability to:

- Track and report on security Findings in context
- Enforce SLAs in context
- Handle False Positives, Risk Acceptances and other triage decisions
- Distill duplicates using DefectDojo's deduplication algorithm
- Integrate with external Project Tracking software.
- Provide metrics/reports across repositories and development branches using CI/CD integration.
- Coordinate traditional Pen test management.
- Set and enforce SLAs for vulnerability remediation procedures.
- Create and track Risk Acceptances for security vulnerabilities.

Ultimately, DefectDojo's Product:Engagement model allows you to take inventory of your development environment and immediately place new security Findings in context.

---
Here are some examples of ways DefectDojo can be implemented, with DefectDojo co-founder and CTO Matt Tesauro:
<iframe width="560" height="315" src="https://www.youtube.com/embed/44vv-KspHBs?si=OwfGHs2VTQ886-FB" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

---

## DefectDojo Open-Source

DefectDojo's core functionality is available in DefectDojo Open-Source.

This edition of DefectDojo includes:

- Import/Reimport for all 200+ Supported Tools
- REST API
- Deduplication features
- Limited UI, metrics and reporting features
- Jira integration capability

For teams managing a smaller volume of Findings, DefectDojo Open-Source is a great starting point.

### Installation Guides

There are a few supported ways to install DefectDojo’s Open-Source edition ([available on Github](https://github.com/DefectDojo/django-DefectDojo)):

[Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) is the easiest method to install the core program and services required to run DefectDojo.
Our [Architecture](https://docs.defectdojo.com/en/open_source/installation/architecture/) guide gives you an overview of each service and component used by DefectDojo.
[Running In Production](https://docs.defectdojo.com/en/open_source/installation/running-in-production/) lists system requirements, performance tweaks and maintenance processes for running DefectDojo on a production server (with Docker Compose).

Kubernetes is not fully supported at the Open-Source level, but this guide can be referenced and used as a starting point to integrate DefectDojo into Kubernetes architecture.

If you run into trouble with an Open-Source install, we highly recommend asking questions on the [OWASP Slack](https://owasp.org/slack/invite). Our community members are active on the #defectdojo channel and can help you with issues you’re facing.

## 🟧 DefectDojo Pro Edition

<iframe width="560" height="315" src="https://www.youtube.com/embed/XUES0mCCGOI?si=2GEnd1iHlLcQE0R3" title="YouTube video player" frameborder="0" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" referrerpolicy="strict-origin-when-cross-origin" allowfullscreen></iframe>

DefectDojo Inc. hosts a Pro edition of this software for commercial purposes.  Along with a sleek, modern UI, DefectDojo Pro includes:

* [Connectors](/en/connecting_your_tools/connectors/about_connectors/): out-of-the-box API integrations with enterprise-level scanners (such as Checkmarx One, BurpSuite, Semgrep and more)
* **Configurable Import Methods**: [Universal Parser](/supported_tools/parsers/universal_parser/), [Smart Upload](/en/connecting_your_tools/import_scan_files/smart_upload/)
* **[CLI Tools](/en/connecting_your_tools/external_tools/)** for rapid integration with your systems
* **[Additional Project Tracking Integrations](/en/share_your_findings/integrations/)**: ServiceNow, Azure DevOps, GitHub and GitLab
* **[Improved Metrics](/en/customize_dojo/dashboards/pro_dashboards/)** for executive reporting and high-level analysis
* **[Priority And Risk](/en/working_with_findings/finding_priority/)** to identify the Findings of highest urgency, system-wide
* **Premium Support** and implementation guidance for your organization

The Pro edition is available as a cloud-hosted SaaS offering, and is also available for installation on-premises.

For more information on DefectDojo Pro, check out our [Pricing page](https://defectdojo.com/pricing).

## Online Demos

Online demos for both Open-Source and Pro versions of DefectDojo are available.  Both can be accessed using the following credentials:

- Username: `admin`
- Password: `1Defectdojo@demo#appsec`

These demos come loaded with sample data, and are reset on a daily basis.

### Open-Source Demo

A running example of DefectDojo (Open-Source Edition) is available at [https://demo.defectdojo.org/](https://demo.defectdojo.org/).

### Pro Demo

A running example of DefectDojo Pro is available at
[https://pro.demo.defectdojo.com/](https://pro.demo.defectdojo.com/).

## Learning DefectDojo

Whether you’re a Pro or an Open-Source user, we have many resources to help you get started with DefectDojo.

* Our [New User Checklist](/en/about_defectdojo/new_user_checklist/) covers the fundamentals of setting up your DefectDojo environment and establishing your import, triage and reporting workflows.
* Review our supported [security tool integrations](/en/connecting_your_tools/parsers/) to help fit DefectDojo in your DevSecOps program.
* Our team maintains a [YouTube Channel](https://www.youtube.com/@defectdojo) which hosts tutorials, archived Office Hours events, and other content. 

## Connect With Us

To get in touch with the DefectDojo Inc team, you can always reach out to [hello@defectdojo.com](mailto:hello@defectdojo.com).

We regularly on [LinkedIn](https://www.linkedin.com/company/33245534) and also host online presentations for AppSec professionals that can be accessed live or on demand. You can learn about upcoming events on our [Events page](https://defectdojo.com/events) or watch past presentations on our [YouTube Channel](https://www.youtube.com/@defectdojo).

### Stickers

Looking for cool DefectDojo laptop stickers? As a thank you for being a part of the DefectDojo community, you can sign up to get some free DefectDojo stickers. For more information, check out [this link](https://defectdojo.com/defectdojo-sticker-request).