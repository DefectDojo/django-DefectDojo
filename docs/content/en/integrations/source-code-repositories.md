---
title: "Source code repositories"
description: "Integration of repositories to navigate to the locaction of findings in the source code."
draft: false
weight: 5
---

Findings can have a filepath and a line number as the location of the vulnerability. This is typically set when scanning an application with a Static Application Security Test (SAST) tool. If the repository of the source code is specified in the Engagement, DefectDojo will present the filepath as a link and the user can navigate directly to the location of the vulnerability.

## Setting the repository in the Engagement

While editing the Engagement, users can set the URL of the repo. It needs to be the URL including the branch, e.g. https://github.com/DefectDojo/django-DefectDojo/tree/dev (GitHub) or https://gitlab.com/gitlab-org/gitlab/-/tree/master (GitLab).

![Edit Engagement](../../images/source-code-repositories_1.png)

## Link in Finding

When viewing a finding, the location will be presented as a link, if the repository of the source code has been set in the Engagement:

![Link to location](../../images/source-code-repositories_2.png)

Clicking on this link will open a new tab in the browser, with the source file of the vulnerability at the corresponding line number:

![View in repository](../../images/source-code-repositories_3.png)
