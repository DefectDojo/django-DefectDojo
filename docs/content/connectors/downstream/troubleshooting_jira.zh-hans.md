---
title: 排查 Jira 错误（旧版）
description: 修复 Jira 集成问题
weight: 2
aliases:
- /zh-hans/issue_tracking/jira/troubleshooting_jira/
- /zh-hans/en/share_your_findings/troubleshooting_jira/
---

以下是 Jira 集成中一些常见问题及其解决方法。

## 在 DefectDojo 中找不到任何 Jira 设置

如果侧边栏中没有 Jira 菜单、Product / Engagement 表单中没有 Jira 相关区块、发现项上也没有 **Push to Jira** 选项，那么 Jira 集成很可能仍在系统设置中处于禁用状态。DefectDojo 在启用之前会隐藏所有 Jira 相关控件。

请在系统设置页面检查 **Enable Jira Integration**：

* 开源版：⚙️ **Configuration \> System Settings**，然后勾选 **Enable JIRA integration**。表单保存前还需要填写 **Jira webhook secret**，点击 🔄 图标即可生成一个。参见 [Jira 集成指南](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings)。
* Pro 版：**\<Your Edition\> Settings \> System Settings**，然后在 **Jira Integration Settings** 下勾选 **Enable Jira Integration**。参见 [Jira 集成指南](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings)。

如果该设置已经启用，但仍然看不到 Jira 菜单，那么您的用户可能缺少 **View Jira Instance** 配置权限，菜单的显示同样需要该权限。可以直接在用户页面上分配该权限，也可以通过用户组分配。参见[关于权限与角色](/admin/user_management/about_perms_and_roles/#configuration-permissions)。

## DefectDojo 完全无法连接到 Jira（或其他外部服务）

如果 DefectDojo 的 Jira 集成出现类似“connection refused”“no route to host”之类的连接错误，或出现通用的 TLS 握手失败——而且凭据本身是有效的——那么您的 DefectDojo 实例可能位于防火墙之后，出站流量需要经过正向 HTTPS 代理。

对于本地部署的 Pro 版本，请在部署环境中设置 `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` 环境变量。`dojo-compose-cli` 会自动将这些变量传递给 `uwsgi`、`celeryworker` 以及 Connector 容器。完整配置步骤请参见[在正向 HTTPS 代理后运行 DefectDojo](/onprem_deployment/forward_proxy/)。

> 注意：设置 `HTTPS_PROXY` 只会配置 DefectDojo 的**出站**流量。它不会影响 Jira 向 DefectDojo 投递**入站** webhook 的能力——这种情况请参见下方的 [Jira 问题的更改未能更新 DefectDojo 中的发现项](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo)。

## 由于 404、401 或 403 错误，无法在 DefectDojo 中设置 Jira 配置
Jira Cloud：
- 请查阅 Jira Cloud REST API 关于身份验证的文档：https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- 在命令行中验证所提供的凭据是否能访问 Jira 中所需的问题：

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

例如：
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center 或 Server：
- 请查阅 Jira Data Center REST API 关于身份验证的文档：
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ （用户名 + 密码）
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html （个人访问令牌）
- 在命令行中验证所提供的凭据是否能访问 Jira 中所需的问题：

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

例如：
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

使用个人访问令牌时：
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

例如：
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## 不支持 Jira 服务账户

Jira Cloud 服务账户（通过 Atlassian 管理控制台创建）使用的 API 主机与标准用户账户不同，DefectDojo 的 Jira 集成**目前不支持**此类账户。尝试使用服务账户的 API 令牌或 OAuth 2.0 凭据将导致 HTTP 403 错误。

要设置 Jira 集成，请创建一个标准的 Jira 用户账户（带有效邮箱地址），并从该账户生成 API 令牌。如果您希望清晰地标识由 DefectDojo 创建的问题，可以创建一个名为“DefectDojo”之类的专用用户，并使用该用户的 API 令牌进行集成。

## 找不到我的 Space 的 Epic Name ID
某些 Jira Space（例如 Team-Managed Space）不使用 Epic，因此不会有 Epic Name ID。此时，请在 DefectDojo 中将 Epic Name ID 设置为 0。

## 我“推送到 Jira”的发现项没有出现在 Jira 中
使用“Push To Jira”工作流会触发一个异步流程，不过在触发“Push To Jira”后，Jira 中应该会较快地创建出对应的 Issue。

* 检查您的 DefectDojo 通知，确认该流程是否成功。如果推送失败，您会在通知中收到来自 Jira 的错误响应。

未能创建 Issue 的常见原因：
* 您选择的默认 Issue 类型在该 Jira Space 中不可用
* Space 中的 Issue 存在必填属性，导致无法通过 DefectDojo 创建（可以通过 Jira 中的自定义字段来处理）


## 错误：Product 配置有误，或在 Jira 中无权限？

当您尝试将已创建的 Jira 配置添加到某个 Product 时，可能会出现此错误信息。DefectDojo 会尝试验证与 Jira 的连接，如果连接失败，就会抛出此错误信息。

* 检查您的 Jira 凭据是否被允许在所选的 Jira Space 中创建 Issue。
* “Project Key”字段必须是有效的 Jira Space。同一个 Space 内的 Jira Issue 可以使用多个不同的 Key；确认 Project Key 最简单的方法是查看该 Jira Space 的 URL：通常会是 `https://xyz.atlassian.net/jira/core/projects/JTV/board` 这样的形式。此例中 `JTV` 即为 Space Key。

## 对 Jira 问题所做的更改未能更新 DefectDojo 中的发现项

* 首先确认 DefectDojo 的 webhook 接收端配置正确，并且能够成功接收更新。

* 确认 Defect Dojo 使用的 SSL 证书受 JIRA 信任。对于 JIRA Cloud，您必须使用[由全球受信任的证书颁发机构签发的有效 SSL/TLS 证书](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)

* 如果您正在尝试推送状态变更，请确认 Jira 转换（transition）映射设置正确（Reopen / Close Transition ID）。

* 使用公共端点（例如 Pipedream 或 Beeceptor）来[测试](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/)您的 JIRA webhook：

* 确认该发现项确实与 Jira 问题相关联。如果该 Issue 未关联到某个 DefectDojo 发现项，webhook 请求仍会被接受（HTTP `200`），但不会更新任何发现项。

* 请记住，该端点**始终返回 HTTP `200`**，无论是否实际执行了更新。发送方（系统 webhook 或 Jira Automation 规则）收到的 `200` 并不能确认更改已到达某个发现项——请检查响应体和 DefectDojo 日志以查看实际结果。

* 如果您使用的是 **Jira Automation**（*Send web request*）而不是系统 webhook，请检查以下几点：
    * 请求的 **Body** 设置为 **Custom data**，并且顶层包含 `webhookEvent` 字段，其值为 `"jira:issue_updated"` 或 `"comment_created"`。**Empty** 和 **Jira issue data** 这两种 body 选项会省略该字段，而 DefectDojo 会忽略任何 `webhookEvent` 无法识别的请求。
    * 请求上设置了 `Content-Type: application/json`——DefectDojo 会拒绝任何其他内容类型。
    * 对于问题更新，`issue.id` 必须是**数字型**的 Jira Issue ID（`{{issue.id}}`），而不是 Issue Key，并且 `resolution` 与 `updated` 字段都必须存在（`resolution` 可以为 `null`）。缺少 `resolution` 或 `updated` 会导致请求被静默跳过。
    * 对于评论，`comment.self` URL 的 `.../issue/<id>/comment/...` 部分中包含数字型的 `{{issue.id}}`，并且 `body` 与 `updateAuthor` 都必须存在。
    * 如果评论没有出现，请检查**循环防护**：当评论作者与 DefectDojo 用于发布评论的 Jira 账户一致时，DefectDojo 会跳过该评论。如果希望摄取这些评论，请以不同的 Jira 用户运行该 Automation 规则。
    * 使用 Automation 的 payload 预览来确认智能值（smart value）能按预期解析——它们的名称在不同 Jira 实例之间可能会有所不同。

## Jira Epic 未能创建

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

DefectDojo 的 Jira 集成需要一个名为“Epic Name”的自定义字段值。然而，您的 Project 设置在创建 Epic 时可能实际上并未使用“Epic Name”这一字段。Atlassian 在 [2023 年 8 月](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562)进行了一次变更，将“Epic Name”与“Epic Summary”字段合并了。

较新的 Jira Space 在默认创建 Epic 时可能不会使用该字段，从而导致出现此错误信息。

要解决此问题，您可以将“Epic Name”字段添加到您的 Project 的 Issue 创建界面：

1. 尝试在 Jira 中手动创建一个 Epic（通过 Jira 界面）。
2. 打开“...”菜单
3. 点击“Find Your Field”
4. 输入“Epic Name”
5. 按照 Jira 的说明，将 Epic Name 添加为该界面的字段。

![image](images/epic_name_error.png)

## 配置 JIRA 连接重试与超时

DefectDojo 的 JIRA 集成包含可配置的重试与超时设置，用于处理速率限制和连接问题。这些设置对于保持系统的响应能力十分重要，在使用 Celery worker 时尤为如此。

### 可用的配置变量

以下环境变量用于控制 JIRA 连接行为：

- **`DD_JIRA_MAX_RETRIES`**（默认值：`3`）：针对可恢复错误的最大重试次数。该集成会在遇到 HTTP 429（Too Many Requests）、HTTP 503（Service Unavailable）以及连接错误时自动重试。详情请参见 [JIRA 速率限制文档](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/)。

- **`DD_JIRA_CONNECT_TIMEOUT`**（默认值：`10` 秒）：建立与 JIRA 服务器连接时的连接超时时间。

- **`DD_JIRA_READ_TIMEOUT`**（默认值：`30` 秒）：连接建立后，等待 JIRA 服务器响应的读取超时时间。

**关于速率限制的说明**：jira 库内置了针对速率限制重试的最长等待时间，为 60 秒。如果 JIRA 的 `Retry-After` 响应头指示的等待时间超过 60 秒，请求将会失败且不会重试。这是当前所使用的 jira 库版本的一个限制。

### 为何保守的取值很重要

**重要**：建议为这些设置使用保守（较低）的取值。原因如下：

1. **Celery 任务阻塞**：DefectDojo 中的 JIRA 操作以异步 Celery 任务的形式运行。当某个任务处于重试延迟等待状态时，会阻塞该 Celery worker 处理其他任务。

2. **worker 池耗尽**：如果多个 JIRA 操作都在以较长的延迟进行重试，您的 Celery worker 池可能会很快被耗尽，导致其他任务（不仅限于与 JIRA 相关的任务）排队等待。

3. **系统响应能力**：较长的重试延迟会让系统显得无响应，在 JIRA 出现故障或触发速率限制时尤为明显。

JIRA 速率限制是新增功能，欢迎在 Slack 或 GitHub 上告诉我们哪些设置对您最有效。

## Jira 与 DefectDojo 不同步

有时 Jira 会宕机，或 DefectDojo 会宕机，又或者 webhook 中存在 bug。在这些情况下，Jira 可能会与 DefectDojo 变得不同步。如果大量问题都出现这种情况，手动核对可能不太可行。针对这种场景，DefectDojo 提供了管理命令“jira_status_reconciliation”。

由于该命令需要访问后端，因此 DefectDojo Pro 的 Cloud 用户无法使用；如遇到此问题，请联系我们的支持团队寻求帮助。

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

可以在 uwsgi docker 容器中通过以下方式执行此命令：

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

可以通过 `-v 3` 获取 DEBUG 输出，但前提是先在您的 settings.dist.py 或 local_settings.py 文件中将日志级别提高到 DEBUG

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

命令结束时会打印一份以分号分隔的 CSV 摘要。可以通过将标准输出重定向到文件来捕获它：

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
