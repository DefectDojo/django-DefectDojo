---
title: 审计日志
description: DefectDojo 审计日志中记录的每一次创建、更新和删除操作，以及所捕获的内容和保留期限的配置方法。
draft: false
weight: 4
---

DefectDojo 会记录其数据变更的审计跟踪。每个被跟踪的对象都会自动记录**创建（create）**、**更新（update）**和**删除（delete）**事件，而关系（多对多）表则记录**添加（add）**和**移除（remove）**事件。

## 工作原理

审计跟踪由针对每个模型注册的数据库触发器驱动。对于每个被跟踪的对象，可能触发三种事件类型：

| 事件类型    | 触发时机                                                                 | 操作     |
| ------------- | ----------------------------------------------------------------------------- | ---------- |
| `InsertEvent` | 新建一条记录时                                                        | **创建（Create）** |
| `UpdateEvent` | 记录发生变化时——仅当某个字段的值确实发生了变化               | **更新（Update）** |
| `DeleteEvent` | 删除一条记录时                                                            | **删除（Delete）** |

多对多关系表（标签、审阅人、防火墙 IP 范围）只跟踪**添加**（`InsertEvent`）和**移除**（`DeleteEvent`）——关系行没有"更新"这一说。

### 每个事件都会捕获的内容

- **Who（操作者）** — 执行操作的用户，取自请求上下文。
- **When（时间）** — 一个时间戳。
- **Source IP（来源 IP）** — 远程地址，会遵循 `X-Forwarded-For` 代理链。
- **Before/after snapshot（变更前后快照）** — 该记录的完整字段值。
- **Context / label（上下文/标签）** — 将源自同一请求的事件归为一组。标签
  `initial_backfill` 用于标记在审计跟踪首次启用时导入的历史记录。

后台任务产生的事件会被追溯拼接回其源请求的上下文，因此即使某个操作是异步完成的，依然会归属于触发它的用户。

## 核心版（开源）— 已跟踪的操作

| 对象                         | 创建 | 更新 | 删除 | 说明                                          |
| ------------------------------ | :----: | :----: | :----: | ---------------------------------------------- |
| User（用户）                           |   ✅   |   ✅   |   ✅   | 快照中排除 `password` 字段             |
| Product Type（产品类型）                   |   ✅   |   ✅   |   ✅   |                                                |
| Product（产品）                        |   ✅   |   ✅   |   ✅   |                                                |
| Engagement（测试活动）                     |   ✅   |   ✅   |   ✅   |                                                |
| Test（测试）                           |   ✅   |   ✅   |   ✅   |                                                |
| Finding（发现项）                        |   ✅   |   ✅   |   ✅   |                                                |
| Finding Group（发现项组）                  |   ✅   |   ✅   |   ✅   |                                                |
| Finding Template（发现项模板）               |   ✅   |   ✅   |   ✅   |                                                |
| Risk Acceptance（风险接受）                |   ✅   |   ✅   |   ✅   |                                                |
| Endpoint（端点）                       |   ✅   |   ✅   |   ✅   |                                                |
| Location（位置）                       |   ✅   |   ✅   |   ✅   |                                                |
| URL                            |   ✅   |   ✅   |   ✅   |                                                |
| Notification Webhook（通知 Webhook）           |   ✅   |   ✅   |   ✅   | 排除 `header_name` / `header_value`（敏感信息） |

### 核心版 — 关系（添加/移除）事件

| 关系                       | 添加 | 移除 |
| ---------------------------------- | :-: | :----: |
| Finding → Reviewers（发现项 → 审阅人）                | ✅  |   ✅   |
| Finding → Tags（发现项 → 标签）                     | ✅  |   ✅   |
| Finding → Inherited Tags（发现项 → 继承标签）           | ✅  |   ✅   |
| Product → Tags（产品 → 标签）                     | ✅  |   ✅   |
| Engagement → Tags（测试活动 → 标签）                  | ✅  |   ✅   |
| Engagement → Inherited Tags（测试活动 → 继承标签）        | ✅  |   ✅   |
| Test → Tags（测试 → 标签）                        | ✅  |   ✅   |
| Test → Inherited Tags（测试 → 继承标签）              | ✅  |   ✅   |
| Endpoint → Tags（端点 → 标签）                    | ✅  |   ✅   |
| Endpoint → Inherited Tags（端点 → 继承标签）          | ✅  |   ✅   |
| Finding Template → Tags（发现项模板 → 标签）            | ✅  |   ✅   |
| App Analysis (Technology) → Tags（应用分析（技术）→ 标签）   | ✅  |   ✅   |
| Objects/Product → Tags（对象/产品 → 标签）             | ✅  |   ✅   |

## Pro 版 — 已跟踪的操作

| 对象                            | 创建 | 更新 | 删除 | 说明                          |
| --------------------------------- | :----: | :----: | :----: | ------------------------------ |
| Enhanced Finding（增强型发现项）                  |   ✅   |   ✅   |   ✅   | Finding 在 Pro 版中的配套对象       |
| Rule（规则）                              |   ✅   |   ✅   |   ✅   | 规则引擎                   |
| Rule Action（规则动作）                       |   ✅   |   ✅   |   ✅   |                                |
| Rule Action Condition（规则动作条件）             |   ✅   |   ✅   |   ✅   |                                |
| Rule Filter Entry（规则筛选条目）                 |   ✅   |   ✅   |   ✅   |                                |
| Rules Engine Operation（规则引擎操作）            |   ✅   |   ✅   |   ✅   |                                |
| Rules Engine Operation Message（规则引擎操作消息）    |   ✅   |   ✅   |   ✅   |                                |
| Scheduled Task（计划任务）                    |   ✅   |   ✅   |   ✅   |                                |
| Scheduled Task Run（计划任务运行）                |   ✅   |   ✅   |   ✅   |                                |
| Mitigation Policy（缓解策略）                 |   ✅   |   ✅   |   ✅   |                                |
| Tunable Setting（可调设置）                   |   ✅   |   ✅   |   ✅   | 系统配置变更   |
| Feature Flag State（功能开关状态）                |   ✅   |   ✅   |   ✅   | 开关切换 + 系统固定项     |
| Feature Flag Definition（功能开关定义）           |   ✅   |   ✅   |   ✅   | 元数据/注册表同步       |
| Cloud Firewall（云防火墙）                    |   ✅   |   ✅   |   ✅   | 排除 `locked` 字段        |
| Firewall IP Mask（防火墙 IP 掩码）                  |   ✅   |   ✅   |   ✅   |                                |

### Pro 版 — RBAC/权限

| 对象                        | 创建 | 更新 | 删除 |
| ----------------------------- | :----: | :----: | :----: |
| Group（组）                         |   ✅   |   ✅   |   ✅   |
| Role（角色）                          |   ✅   |   ✅   |   ✅   |
| Group Membership（组成员身份）              |   ✅   |   ✅   |   ✅   |
| Global Role（全局角色）                   |   ✅   |   ✅   |   ✅   |
| Product Group Assignment（产品组分配）      |   ✅   |   ✅   |   ✅   |
| Product Type Group Assignment（产品类型组分配） |   ✅   |   ✅   |   ✅   |
| Product Member（产品成员）                |   ✅   |   ✅   |   ✅   |
| Product Type Member（产品类型成员）           |   ✅   |   ✅   |   ✅   |

### Pro 版 — 关系（添加/移除）事件

| 关系                | 添加 | 移除 |
| --------------------------- | :-: | :----: |
| Cloud Firewall → IP Ranges（云防火墙 → IP 范围）  | ✅  |   ✅   |

## 配置与保留（本地部署控制项）

| 设置项              | 环境变量                  | 默认值            | 作用                                                              |
| -------------------- | -------------------------------------- | ------------------ | ------------------------------------------------------------------ |
| 启用审计日志 | `DD_ENABLE_AUDITLOG`                  | `True`             | 设为 `False` 时，所有历史触发器都会被禁用，不再记录任何事件 |
| 保留期限     | `DD_AUDITLOG_FLUSH_RETENTION_PERIOD`  | `-1`（永不清理） | 保留历史记录的月数；更早的事件会由清理任务批量删除  |
| 清理批次大小     | `DD_AUDITLOG_FLUSH_BATCH_SIZE`        | `1000`             | 清理过程中每批删除的行数                              |
| 单次清理最大批次数    | `DD_AUDITLOG_FLUSH_MAX_BATCHES`       | `100`              | 每次清理运行的批次数量上限                        |

## 说明与限制

- **绝不会捕获敏感信息。** 用户密码和通知 Webhook 的请求头值会被明确排除在事件快照之外。
- **只有发生真实变更时才会记录更新。** 未改变任何字段值的保存操作不会产生更新事件；仅有
  `last_updated` 等自动维护字段发生变化也不会触发更新事件。
- **身份验证事件不在此处记录。** 这里只记录数据变更。登录、登出和登录失败等活动由其他机制单独处理，不属于本审计日志的一部分。
