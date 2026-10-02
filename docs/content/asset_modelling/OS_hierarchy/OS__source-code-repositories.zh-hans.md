---
title: 将发现项链接到源代码
description: 集成代码仓库以便跳转到发现项在源代码中的位置。
draft: false
weight: 5
audience: opensource
aliases:
- /zh-hans/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

某些工具(尤其是 SAST 工具)会在漏洞数据中包含相关的文件名和行号。如果在测试活动(Engagement)中指定了源代码的代码仓库,DefectDojo 会将文件路径显示为链接,用户可以直接跳转到该漏洞所在的位置。

## 在测试活动和测试中设置代码仓库

### 测试活动(Engagement)

在编辑测试活动时,用户可以设置特定源代码管理(SCM)仓库的 URL。**(在 Pro UI 中,可在 Edit Engagement > Optional Fields > Repo 下设置此字段。)**

对于交互式测试活动(Interactive Engagement),该 URL 需要指定分支:
- 对于 GitHub——例如 https://github.com/DefectDojo/django-DefectDojo/tree/dev
![编辑测试活动(GitHub)](images/source-code-repositories_1.png)
- 对于 GitLab——例如 https://gitlab.com/gitlab-org/gitlab/-/tree/master
![编辑测试活动(GitLab)](images/source-code-repositories-gitlab_1.png)
- 对于公开的 BitBucket——例如    (类似 git clone 使用的 url)
![编辑测试活动(Bitbucket 公开仓库)](images/source-code-repositories-bitbucket_1.png)
- 对于独立部署/本地部署(standalone/onpremise)的 BitBucket,例如 https://bb.example.com/scm/some-project/some-repo.git,或对于用户的公开仓库,例如 https://bb.example.com/scm/some-user-name/some-repo.git(类似 git clone 使用的 url)
![编辑测试活动(Bitbucket 独立部署)](images/source-code-repositories-bitbucket-onpremise_1.png)

对于 CI/CD 测试活动,提交哈希(commit hash)、分支/标签以及代码行号可能会有所变化,因此您只需提供仓库的 URL 即可。
- 对于 GitHub——例如 `https://github.com/DefectDojo/django-DefectDojo`
- 对于 GitLab——例如 `https://gitlab.com/gitlab-org/gitlab`
- 对于公开的 BitBucket、Gitea 和 Codeberg——例如 `https://bitbucket.org/some-user/some-project.git`(类似 git clone 使用的 url)
- 对于独立部署/本地部署的 BitBucket,例如 `https://bb.example.com/scm/some-project.git`,或对于用户的公开仓库,例如 `https://bb.example.com/scm/some-user-name/some-repo.git`(类似 git clone 使用的 url)

在 CI/CD 测试活动中,您可以在 **Edit Engagement** 表单中指定提交哈希或分支/标签,DefectDojo 渲染链接时会将其附加到链接末尾。如果未设置这些内容,则 SCM URL 必须包含完整的链接,其中需包含代码分支。

SCM 跳转链接由仓库 URL 结合 SCM 类型组成。可以在资产(Asset)的自定义字段 "scm-type" 中设置特定的 SCM 类型。如果未设置 "scm-type",且 URL 中包含 "https://github.com",则会默认采用 "github" 作为 SCM 类型。

资产自定义字段:

![资产自定义字段](images/asset-custom-fields_1.png)

添加资产 SCM 类型:

![资产 SCM 类型](images/asset-scm-type_1.png)

可选的 SCM 类型包括 'github'、'gitlab'、'bitbucket'、'bitbucket-standalone'、'gitea'、'codeberg',或留空(默认使用 github)。


## 发现项中的源代码链接

在查看某个发现项时,如果该测试活动已设置源代码的代码仓库,则漏洞位置会显示为一个链接:

![指向位置的链接](images/source-code-repositories_2.png)

点击该链接会在浏览器中打开一个新标签页,并定位到该漏洞对应行号的源代码文件:

![在代码仓库中查看](images/source-code-repositories_3.png)
