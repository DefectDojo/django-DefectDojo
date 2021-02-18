---
title: "DefectDojo\'s Documentation"
date: 2021-02-02T20:46:29+01:00
draft: false
---

# DefectDojo\'s Documentation

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

DefectDojo is based on a model that allows the ultimate flexibility in
your test tracking needs.

-   Working in DefectDojo starts with a `Product Type`.
-   Each Product Type can have one or more `Products`.
-   Each Product can have one or more `Engagements`.
-   Each Engagement can have one or more `Tests`.
-   Each Test can have one or more `Findings`.

![image](images/DD-Hierarchy.png)

The code is open source, and [available on
github](https://github.com/DefectDojo/django-DefectDojo) and a running
example is available on [the demo server](https://demo.defectdojo.org)
using the credentials `admin` / `defectdojo@demo#appsec`. Note: The demo
server is refreshed regularly and provisioned some sample data.

Our documentation is organized in the following sections:

{{% children depth="2" %}}