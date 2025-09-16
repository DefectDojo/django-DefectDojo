---
title: "Link Findings to source code"
description: "Integration of repositories to navigate to the locaction of findings in the source code."
draft: false
weight: 5
---

Certain tools (particularly SAST tools) will include the associated file name and line number in vulnerability data. If the repository of the source code is specified in the Engagement, DefectDojo will present the filepath as a link and the user can navigate directly to the location of the vulnerability.

## Setting the repository in the Engagement and Test

### Engagement

While editing the Engagement, users can set the URL of the specific Source Code Management repo.  **(In the Pro UI, this field can be set under Edit Engagement > Optional Fields > Repo)**.

For an Interactive Engagement, it needs to be a URL that specifies the branch:
- for GitHub - like https://github.com/DefectDojo/django-DefectDojo/tree/dev
![Edit Engagement (GitHub)](images/source-code-repositories_1.png)
- for GitLab - like https://gitlab.com/gitlab-org/gitlab/-/tree/master
![Edit Engagement (Gitlab)](images/source-code-repositories-gitlab_1.png)
- for public BitBucket - like    (like git clone url)
![Edit Engagement (Bitbucket public)](images/source-code-repositories-bitbucket_1.png)
- for standalone/onpremise BitBucket https://bb.example.com/scm/some-project/some-repo.git or https://bb.example.com/scm/some-user-name/some-repo.git for user public repo (like git clone url)
![Edit Engagement (Bitbucket standalone)](images/source-code-repositories-bitbucket-onpremise_1.png)

For CI/CD Engagements, the commit hash, branch/tag and code line can vary, so you only need to include the URL of the repository.
- for GitHub - like `https://github.com/DefectDojo/django-DefectDojo`
- for GitLab - like `https://gitlab.com/gitlab-org/gitlab`
- for public BitBucket, Gitea and Codeberg - like `https://bitbucket.org/some-user/some-project.git` (like git clone url)
- for standalone/onpremise BitBucket `https://bb.example.com/scm/some-project.git` or `https://bb.example.com/scm/some-user-name/some-repo.git` for user public repo (like git clone url)

In a CI/CD Engagement, you can specify a commit hash or branch/tag in the **Edit Engagement** form, which will be appended to any links rendered by DefectDojo.  If these are not set, the SCM URL will need to contain a complete link which includes the code branch. 

SCM navigation URL is composed from Repo URL using SCM Type. A specific SCM type can be set in Product custom field "scm-type". If no "scm-type" is set and the URL contains "https://github.com", a "github" SCM type is assumed.

Product custom fields:

![Product custom fields](images/product-custom-fields_1.png)

Product SCM type add:

![Product scm type](images/product-scm-type_1.png)

Possible SCM types could be 'github', 'gitlab', 'bitbucket', 'bitbucket-standalone', 'gitea', 'codeberg' or nothing (for default github).


## Source code Links in Findings

When viewing a finding, the location will be presented as a link, if the repository of the source code has been set in the Engagement:

![Link to location](images/source-code-repositories_2.png)

Clicking on this link will open a new tab in the browser, with the source file of the vulnerability at the corresponding line number:

![View in repository](images/source-code-repositories_3.png)
