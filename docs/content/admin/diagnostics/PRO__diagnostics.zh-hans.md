---
title: 诊断
description: 查阅跨子系统的集成尝试台账：记录了哪些内容、如何筛选、如何避免记录凭据，以及谁可以查看技术细节
weight: 1
audience: pro
---

诊断（Diagnostics）是一份统一台账，记录了 DefectDojo 与外部系统通信的每一次尝试，也记录了其他系统与它通信的尝试。当工单一直没有出现、扫描始终未导入，或用户无法登录时，这个页面会告诉你发生了什么、发生在何时、涉及哪项配置，以及是谁触发的。

诊断是 **DefectDojo Pro** 功能。可在 **Connect > Diagnostics** 下找到它。

![诊断台账，错误视图](images/diagnostics_errors.png)

## 记录了哪些内容

每次尝试都会写入一行记录，涵盖所有会与 DefectDojo 外部通信的子系统：

| 来源 | 产生记录的场景 |
| --- | --- |
| **连接器（Connector）** | 上游连接器的发现和同步运行 |
| **下游集成器（Downstream integrator）** | 推送到 Jira、GitHub、GitLab、ServiceNow 及其他下游连接器 |
| **Jira** | 旧版 Jira 集成：推送、评论和预览 |
| **SSO（OIDC/OAuth2）** | 通过 OAuth 提供商进行的登录尝试 |
| **SAML** | SAML 断言，包括签名和属性失败 |
| **LDAP** | LDAP 绑定和查找 |
| **导入 / 重新导入（Import / Reimport）** | 扫描上传，无论通过 UI、API 还是计划任务 |
| **规则引擎（Rules engine）** | 规则评估及其尝试执行的操作 |
| **计划任务（Scheduling）** | 计划运行，包括从未启动的运行 |
| **Sensei** | 代码仓库扫描和修复运行 |
| **通知（Notification）** | 出站通知投递 |
| **系统（System）** | 不属于任何产品的实例级活动 |

记录是与子系统*并行*写入的，绝不会取代子系统本身。每个适配器都挂接在源记录上，并被刻意设计为故障安全（fail-safe）：如果写入诊断记录时出错，该错误会被吞掉，原始操作会继续进行。因此，诊断功能永远不会成为推送、导入或登录失败的原因。

由于记录是以产生它们的源记录为键的，重新保存某个源记录会更新其已有的诊断记录，而不会新增一条重复记录。一次尝试在其整个生命周期内始终对应一行记录，从 `Queued` 经过 `Running` 直到得出结果。

### 记录中的字段

| 字段 | 含义 |
| --- | --- |
| **When** | 记录写入的时间；**Started**、**Finished** 和 **Duration** 描述的是尝试本身的时间信息 |
| **Source** | 子系统，取自上表 |
| **Provider** | 该来源下具体的工具或提供商（如 `jira`、`github`、`okta`，或某个扫描器名称） |
| **Operation** | 所尝试执行的操作（`push`、`sync`、`login`、`reimport`、`rule_run`） |
| **Status** | `Queued`、`Running`、`Success`、`Failed`、`Timed out`、`Skipped` 或 `Dry run` |
| **Severity** | `Info`、`Warning`、`Error` 或 `Critical` |
| **Summary** | 一行结果摘要，可一目了然地安全查看 |
| **Trigger** | 触发该尝试的方式：`UI`、`API`、`Scheduled`、`Webhook`、`Automatic`、`Command line` 或 `System` |
| **Triggered by** | 负责该操作的用户，若为无人值守的操作则显示 `System` |
| **Asset** | 该尝试所属的产品；为空表示是实例级别的 |
| **Related object** | 该尝试所涉及的发现项、测试活动或其他记录 |
| **Configuration** | 使用的是哪一项配置，以其标签标识 |
| **External reference** | 另一系统返回的标识符，例如所创建工单的编号 |
| **Correlation ID** | 将同一逻辑操作产生的多条记录关联在一起 |
| **Reported detail** 和 **Context** | 完整的技术细节（受限查看，参见 [谁能看到什么](#who-sees-what)） |

## 四种视图

表格上方的标签页是预先保存好的起点，而不是需要你重新搭建的筛选条件：

* **Errors（错误）** — 失败和超时。应首先打开的视图。
* **Successes（成功）** — 证明一项正常工作的集成确实在正常工作，当有人反馈"什么都没有同步"时很有用。
* **Never completed（从未完成）** — 早已过了应完成时间、却仍处于 `Queued` 或 `Running` 状态的尝试。这些是"沉默"的问题：没有任何失败，因此也没有任何报错，但结果也始终没有到达。
* **All events（所有事件）** — 全部内容，不做任何筛选。

![所有事件，显示全部来源](images/diagnostics_all_events.png)

当前所选视图会体现在页面 URL 中，因此某个视图是可链接的，刷新页面后依然保留。

## 缩小列表范围

* **Time range（时间范围）** — 24 小时、7 天、30 天或 90 天，可在页头的按钮中选择。
* **Source counts（来源计数）** — 汇总卡片下方的彩色计数同时也是快捷筛选器。点击其中一个即可只显示该来源；再次点击（或点击 **Clear source filter**）即可返回。同一时间只能激活一个或不激活任何一个。
* **Per-column filters and sorting（按列筛选和排序）** — 每一列都支持筛选和排序，包括 Severity 和 Source。Severity 按严重程度排序（`Critical` → `Info`），而不是按字母顺序；Source 按你看到的标签排序，而不是按其底层存储的值排序。
* **Keyword Search（关键字搜索）** — 同时搜索所有文本字段。
* **Column preferences（列首选项）** — 列选择器及其已保存的布局，行为与其他所有 Pro 列表页面一致。

![用作快捷筛选器的来源计数](images/diagnostics_chip_filter.png)

点击某一行开头的放大镜图标，即可打开该次尝试的完整详情：

![单个事件，包含脱敏提示](images/diagnostics_detail.png)

## 记录写入前会先移除凭据

集成错误会引用失败的请求内容，而这些引用中可能带有敏感信息：一个 `Authorization` 请求头、查询字符串中的令牌、连接 URL 中的密码。诊断功能会**在写入之前**先将其剥离，因此原始值永远不会进入数据库，日后也不会因为某个疏忽而泄露。

有两类内容会被清除：

* **凭据形态键名下的值** — 任何键名看起来像是敏感信息的字段（`password`、`token`、`secret`、`api_key`、`authorization`、`private_key` 及类似名称，不区分大小写，也不论是否带连字符或空格）。有一小部分键名例外，因为重要的只是它们*是否存在*，而不是其内容。
* **无论出现在何处、看起来像凭据的值** — bearer 和 basic 授权请求头、JWT、嵌入在 URL 中的凭据（`https://user:pass@host`）、可识别的厂商令牌前缀，以及 PEM 代码块。

这些内容都会被替换为 `[redacted]`。周围的信息会被保留，因此错误信息依然可读：

```text
401 Unauthorized: Authorization: [redacted]
upload rejected: https://svc:[redacted]@sftp.example/out/…
```

过长的值会被截断，嵌套层级很深的上下文也会被展平，这样一个巨大的负载就不会把表格撑得过大。

只要某一行中的内容被移除过，该行就会明确标注这一点，而不会让你去猜测某个字段究竟是本来为空，还是被清空的。

> **脱敏处理设计上只是尽力而为。** 清除机制识别的是凭据的*形态*。如果某个敏感信息看起来像普通文字，且所在的键名也不像是敏感字段，它仍然可能被记录下来。请把诊断功能当作一份运维日志，而不要认为其中一定不含任何敏感信息——并且应将技术细节的可见范围限制在确实需要的人员范围内。

## 谁能看到什么

诊断功能的可见性是分层的，因为失败的摘要信息对产品负责人有用，而其背后的原始请求内容则不然。

| | 超级用户 | 其他所有人 |
| --- | --- | --- |
| 其被授权访问的产品所对应的记录 | 是 | 是 |
| 实例级记录（不属于任何产品） | 是 | 否 |
| 摘要、来源、状态、严重程度、时间信息、配置 | 是 | 是 |
| **Reported detail**、**Context**、**Remote IP** | 是 | 隐藏，并标注为已隐藏 |

非超级用户会看到某项细节确实存在但被隐藏了，而不是一个看起来像数据缺失的空字段。实例级记录——SSO、SAML、LDAP 以及其他不属于任何产品的活动——仅限超级用户查看，因为没有任何产品成员身份能够授予对它们的访问权限。

## 记录保留多长时间

一项计划任务会定期清理台账，防止其无限增长：

| 严重程度 | 保留时长 |
| --- | --- |
| `Info` | 30 天 |
| `Warning`、`Error`、`Critical` | 180 天 |

这两个保留期都可以通过 `DIAGNOSTIC_EVENT_INFO_RETENTION_DAYS` 和 `DIAGNOSTIC_EVENT_RETENTION_DAYS` 设置项进行配置。删除操作分批执行，因此一次大规模清理不会长时间占用事务。

## API

该台账通过 API 只能读取，路径为 `/api/v2/diagnostic_events/`：

| 端点 | 返回内容 |
| --- | --- |
| `GET /api/v2/diagnostic_events/` | 列表，可结合下方的筛选条件 |
| `GET /api/v2/diagnostic_events/{id}/` | 单个事件 |
| `GET /api/v2/diagnostic_events/summary/` | 页头卡片背后的计数，包括按来源统计的数量 |
| `GET /api/v2/diagnostic_events/choices/` | `source`、`status`、`severity` 和 `trigger` 的有效取值 |

常用参数：

| 参数 | 作用 |
| --- | --- |
| `source`、`status`、`severity`、`trigger` | 可同时接受多个以逗号分隔的值 |
| `failures_only=true` | 失败和超时 |
| `unresolved_only=true` | 仍处于排队或运行中的尝试 |
| `product_name` | 按产品名称筛选 |
| `object_model` | 按尝试所涉及的记录类型筛选 |
| `o=` | 排序，前面加 `-` 表示逆序（`o=-created_at`） |

同样的访问规则在此依然适用：非超级用户只能获取限定在其产品范围内的记录，且受限字段会被隐藏。

## 排查问题所在

* **工单一直没有出现。** 将 Source 筛选为对应的集成器（或 Jira），然后查看 Status。`Failed` 会在 Summary 中给出原因；如果早已过了预期时间却仍是 `Queued`，说明该任务根本没有运行，这是工作进程或调度方面的问题，而不是凭据问题。
* **用户无法登录。** 将 Source 筛选为 SSO、SAML 或 LDAP，查看其登录尝试的失败原因——可能是断言签名有误、绑定被拒绝，或属性不匹配。这些记录属于实例级别，仅限超级用户查看。
* **扫描没有出现。** 将 Source 筛选为 Import / Reimport。查看 Trigger 可以区分是无人值守的计划上传还是某人手动上传的，查看 Triggered by 可以知道该找谁询问。
* **某件事似乎在无休止地重试。** 按 Correlation ID 排序，或按某个 Correlation ID 筛选，即可将同一逻辑操作的所有尝试集中查看。
* **"什么都不工作了。"** 先打开同一时间范围内的 Successes 视图。如果那里的列表状况良好，就能把一次含糊的"故障"定位成具体的问题。

## 相关内容

* [功能开关（Feature Flags）](/admin/feature_flags/pro__feature_flags/) — 启用和关闭可选的 Pro 功能
* [连接器（Connectors）](/connectors/upstream/about/) — 拉取发现项
* [Pro 集成（Pro Integrations）](/connectors/downstream/about/) — 推送发现项
* [单点登录（Single Sign-On）](/admin/sso/) — 其登录尝试会出现在此处的身份提供商
