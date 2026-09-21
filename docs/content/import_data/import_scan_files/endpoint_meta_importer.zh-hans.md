---
title: 端点元数据导入器
description: 通过 CSV 批量为端点应用标签和自定义字段
weight: 4
audience: opensource
---

**端点元数据导入器**允许您使用 CSV 文件一次性为大量端点应用标签和自定义字段。这对于运行大规模基础设施扫描的组织尤其有用，因为这些端点需要灵活的元数据以便进行过滤、排序和报告。

## CSV 格式

CSV 文件必须包含一个 `hostname` 列（必填），此外还可以有任意数量的附加列，代表您想要应用的标签或自定义字段。每个附加列的列名将成为标签/字段的键，其行值将成为标签/字段的值。

**示例：**

```
hostname,team,public_facing
sheets.google.com,data analytics,yes
docs.google.com,language processing,yes
feedback.internal.google.com,human resources,no
```

这将应用以下元数据：

| Endpoint | Tags / Custom Fields |
|---|---|
| `sheets.google.com` | `team:data analytics`, `public_facing:yes` |
| `docs.google.com` | `team:language processing`, `public_facing:yes` |
| `feedback.internal.google.com` | `team:human resources`, `public_facing:no` |

## 要求

- `hostname` 列为**必填项**。系统会用它来查找主机名匹配的现有端点，若未找到匹配项则创建新端点。
- 其他所有列名都会被视为标签/自定义字段的键。
- 值以 `key:value` 格式存储。

## 使用端点元数据导入器

在查看某个产品时，端点元数据导入器可从 **端点** 选项卡访问。在此处上传您的 CSV 文件，即可批量为端点应用元数据。
