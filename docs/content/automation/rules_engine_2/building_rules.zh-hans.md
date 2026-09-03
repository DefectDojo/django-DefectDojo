---
title: 构建规则
description: 图形编辑器、触发器、作用范围、条件和消息模板
weight: 2
audience: pro
aliases:
- /zh-hans/automation/rules_engine_v2/building_rules/
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：Rules Engine 2.0 是 DefectDojo Pro 专属功能。</span>

规则是在画布上构建的。您从调色板中拖出节点，将它们连接起来，并在侧边面板中配置每一个节点。本页介绍的是这一过程中不论使用哪些节点都相同的部分。节点本身的说明请见[节点参考](../node_reference/)。

## 编辑器

打开 **Rules Engine 2.0 > All Rules**，选择 **New Rule**，或打开一条已有规则进行编辑。

调色板分为四个类别，这也是条目在典型图中流动的顺序：

| Category | What the nodes do |
|----------|-------------------|
| **Triggers（触发器）** | 决定规则何时被唤醒，以及哪些发现项会进入规则。每张图恰好一个。 |
| **Logic（逻辑）** | 对流经的条目进行路由、限流和去重。 |
| **Findings（发现项）** | 更改发现项。 |
| **Egress（出站）** | 向外发送内容：工单、消息、报告。 |

调色板是由引擎本身生成的，因此您在编辑器中看到的内容，始终与引擎能够执行的内容完全一致。

### 图的规则

图会在您保存时被检查，并在每次运行前再次检查。它必须满足以下所有条件：

* 至少包含一个节点。
* **恰好包含一个**触发器节点。
* 每个节点都有一个唯一、非空、长度不超过 100 个字符的 id。
* 每个节点都是引擎能识别的类型。
* 每条边连接的两个节点都真实存在。
* 不包含环。

一个没有任何连线接入的节点是合法的。它会以空输入列表运行，通常这意味着它不会执行任何操作。

拥有多条入边的节点，会收到这些入边所有输出拼接后的结果。

### 保存前进行预览

**Preview（预览）**会对您当前画布上的图进行一次空跑，并向您展示它会产生的按节点追踪结果：有多少条目进入每个节点、有多少从每个输出离开，以及每个节点原本会做出哪些更改。

Preview 运行的是真实引擎，而不是它的模拟版本，然后会将整个过程回滚。不会写入任何内容，不会记录任何运行，且无论规则的模式如何设置，出站都会被强制模拟。这是检验您的条件是否符合预期的最快方式。

Preview 是唯一会限制其查看的发现项数量的执行方式，以保持速度。当它发生截断时，会在追踪记录中说明这一点。真实运行没有这样的上限。

## 触发器与作用范围

每张图都以三种触发器之一开始。

* **On Finding Event（发现项事件触发）**会在发现项被创建、更新、关闭或重新打开时唤醒规则。可在节点的 **Event** 设置中选择这四者中的哪一个，或选择 `any` 表示全部四种。
* **On a Schedule（按计划触发）**会按照重复的计划周期扫描发现项。
* **Manual Run（手动运行）**会在您对该规则按下 **Run** 时扫描发现项。

### 作用范围（Scope）

三种触发器都接受一个**作用范围（Scope）**，作用范围就是您用来缩小规则考虑范围的方式。它使用的过滤器词汇表与原有 Rules Engine 相同，涵盖发现项及其周边对象的大约六十个过滤器，因此您在那里已经会写的过滤器，在这里含义相同。

关于作用范围，有两点值得了解：

* **作用范围是叠加在授权之上的，绝不会取代授权。** 规则以其所有者的身份运行，因此作用范围是在一组已获授权的发现项之上做进一步缩小。将作用范围留空，并不意味着“实例中的每一个发现项”，而是意味着“规则所有者能看到的每一个发现项”。
* **无效的作用范围会导致运行失败，而不是放宽范围。** 如果某个过滤器键不存在，或某个值是该过滤器会默默丢弃的值，运行就会报错退出。什么都不做的规则是可以恢复的；悄悄编辑实例中每一个发现项的规则则不可以。

对于事件触发器，作用范围充当第二道关卡：事件中指定的发现项会先与作用范围进行匹配，只有通过的那些才会进入图中。

### 计划调度

触发器为 **On a Schedule** 的规则，其计划是在该规则自身上设置的。设置计划需要 Rule Edit 权限，与编辑规则所需的权限相同，因为一条以计划触发的规则在拥有计划之前完全不会执行任何操作。

计划仅限设置在每刻钟的整点上。cron 表达式的分钟字段必须是 `0`、`15`、`30` 或 `45`。

有效示例：

```
0 * * * *     every hour, on the hour
15 9 * * *    every day at 09:15
0 15 * * 1    every Monday at 15:00
30 2 * * *    every day at 02:30
```

## 引用发现项数据

规则中有两个地方会从流经它的条目中读取值：**条件（conditions）**和**模板（templates）**。两者使用相同的点号路径。

```
finding.severity
finding.title
finding.vulnerability_ids.0
product.name
product_type.name
test.scan_type
ctx.rule_name
```

无法解析的路径不会产生错误，而是不产生任何值。

### 可用字段

每个条目都携带一组固定的发现项字段。这份列表是一份契约，因此只会经过深思熟虑之后才会更改。

| Group | Fields |
|-------|--------|
| 标识 | `id`, `title`, `hash_code`, `unique_id_from_tool` |
| 严重程度与评分 | `severity`, `numerical_severity`, `cvssv3`, `cvssv3_score`, `epss_score`, `epss_percentile`, `priority`, `risk`, `risk_score` |
| 文本 | `description`, `mitigation`, `impact` |
| 状态 | `active`, `verified`, `false_p`, `duplicate`, `is_mitigated`, `out_of_scope`, `risk_accepted`, `under_review` |
| 日期 | `date`, `mitigated`, `last_status_update`, `sla_expiration_date` |
| 位置 | `file_path`, `line`, `component_name`, `component_version`, `service` |
| 分类 | `cwe`, `vulnerability_ids`, `tags` |

除 `finding` 外，每个条目还携带 `test`（`id`、`title`、`scan_type`）、`engagement`（`id`、`name`）、`product`（`id`、`name`）、`product_type`（`id`、`name`）以及 `ctx`。

日期是 ISO-8601 字符串。这是刻意为之的：这意味着 `gt` 和 `lt` 作为文本比较时也能正确排序，因此 `2026-07-28` 会被正确判定为大于 `2026-01-01`。

`priority`、`risk` 和 `risk_score` 来自 Pro 的优先级排序功能。尚未被评分的发现项不会携带这些值。

### 条件

**If / Filter** 节点保存一份条件行的列表。每一行由一个路径、一个运算符和一个值组成。**Match** 决定是要求每一行都成立（`all`），还是只要其中一行成立即可（`any`）。

| Operator | Meaning |
|----------|---------|
| `eq` | 等于 |
| `neq` | 不等于 |
| `contains` | 包含 |
| `not_contains` | 不包含 |
| `in` | 属于其中之一 |
| `not_in` | 不属于其中任何一个 |
| `gt` | 大于 |
| `gte` | 大于或等于 |
| `lt` | 小于 |
| `lte` | 小于或等于 |
| `startswith` | 以……开头 |
| `endswith` | 以……结尾 |
| `exists` | 已设置 |
| `not_exists` | 未设置 |

比较是**宽松的**。会先尝试按数字比较，如果失败，则将两个值作为去除首尾空白、不区分大小写的文本进行比较。因此写成 `finding.severity eq high` 的条件，能匹配到严重程度为 `High` 的发现项，这几乎总是作者原本的意图。

#### 转换（Transforms）

条件行可以在比较之前，对读取到的值做后处理。

| Transform | Effect |
|-----------|--------|
| `int` | 整数 |
| `float` | 小数 |
| `str` | 文本 |
| `first` | 列表的第一项 |
| `list` | 作为列表 |
| `join` | 用逗号连接 |
| `upper` | 转为大写 |
| `lower` | 转为小写 |
| `strip` | 去除首尾空白 |
| `cwe_int` | CWE 编号 |
| `severity` | 归一化的严重程度，使不同扫描器中 `critical`、`error`、`warning` 之类的值映射到 DefectDojo 的五个等级上 |
| `numerical_severity` | 可排序的严重程度代码，用于比较排序 |

### 模板

任何标记为消息、备注、标题或值的设置项，都接受 `{{ path }}` 占位符，并按每个条目分别解析：

```
{{finding.severity}}: {{finding.title}} ({{product.name}})
```

没有值的路径会渲染为空字符串。列表会以逗号连接的形式渲染。

模板还能看到一个 `ctx` 区块，携带关于本次运行自身的详情。可用的键取决于具体节点，但常见的有：

| Placeholder | Meaning |
|-------------|---------|
| `{{ctx.rule_name}}` | 规则的名称 |
| `{{ctx.count}}` | 该消息涵盖的发现项数量 |
| `{{ctx.trigger}}` | 启动本次运行的事件 |
| `{{ctx.findings_html}}` | 渲染后的发现项列表，用于邮件节点 |
| `{{ctx.report_url}}` | 下载链接，用于报告节点 |
| `{{ctx.template_name}}` | 报告模板名称，用于报告节点 |

模板只是纯粹的替换。规则配置中的任何地方都不存在表达式求值、代码执行或对象属性访问。

## 安全地测试规则

对于任何会发送内容的规则，建议按以下顺序操作：

1. 构建图，并使用 **Preview** 直到条目数量看起来正确为止。
2. 保存。新建的规则是禁用状态。
3. 将模式保持为 **Simulate**，并启用该规则。
4. 让它运行，然后查看 **Deliveries**，检查记录下来的载荷是否符合您的预期。
5. 将模式切换为 **Live**。

Simulate 不是部分运行。图中的每一次发现项编辑在模拟模式下都会真实发生，只有出站发送会被拦截。
