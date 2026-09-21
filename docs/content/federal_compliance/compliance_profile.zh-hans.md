---
title: 合规档案
description: 将资产注册为一个系统，并设置出现在每份交付物中的基本信息
weight: 1
audience: pro
---

合规档案（Compliance Profile）将某个资产注册为一个系统，并保存出现在其生成的每份交付物中的基本信息。请打开代表您系统边界的资产，进入 **Compliance** 标签页，然后选择 **Profile**。

![合规档案表单](images/01-compliance-profile.png)

## 档案字段

| 字段 | 作用 |
| --- | --- |
| **Enabled**（启用） | 为该产品开启合规跟踪。 |
| **Automatic Sync**（自动同步） | 使 POA&M 条目与发现项保持同步。 |
| **POA&M ID Prefix**（POA&M ID 前缀） | 条目编号。必填。条目默认按 `V-1`、`V-2` 等方式编号。 |
| **Impact Level**（影响级别） | LI-SaaS、Low、Moderate 或 High。 |
| **Cloud Service Provider**（云服务提供商） | CSP 名称，将按此显示在 POA&M 封面信息中。 |
| **System / Offering Name**（系统 / 产品名称） | 系统名称，将按此显示在 POA&M 封面信息中。 |
| **FedRAMP System Identifier**（FedRAMP 系统标识符） | 您系统的标识符，例如 `F00000042`。 |
| **Default Point of Contact**（默认联系人） | 应用于未指定自身联系人的条目。 |
| **Scan Item Policy**（扫描条目策略） | 可选择包含所有未结条目，或仅包含已逾期的扫描条目。 |
| **OSCAL SSP Reference**（OSCAL SSP 引用） | 可选。设置后，生成的 OSCAL POA&M 会通过 `import-ssp` 引用该地址。 |

### 选择扫描条目策略

仅逾期是 FedRAMP ConMon 的最低要求。**Include all open items**（包含所有未结条目）是更保守的选择，也是默认设置。

## 保存与同步

**Save Compliance Profile**（保存合规档案）会完成该资产的注册。随后，POA&M 台账会根据该资产的现有发现项自动生成条目，Compliance 标签页的其余部分也随之可用。

开启 **Automatic Sync**（自动同步）后，台账会自动保持最新——参见[POA&M 台账](../poam_ledger)。**Sync POA&M Now**（立即同步 POA&M）会立即执行一次同步，在您刚更改档案设置或导入新扫描后使用会很有帮助。

## 仅可通过 API 设置的选项

有两项档案设置未出现在表单中，需要通过合规 API 进行设置：

* **Default scan controls**（默认扫描控制项）——归因于那些本身不带控制映射的扫描器发现项的控制项。对于漏洞扫描结果，常见选择是 `RA-5`。而*确实*携带自身控制引用的发现项，则会依据这些引用进行映射；参见[控制覆盖情况](../control_coverage)。
* **Configuration test types**（配置测试类型）——其发现项会被视为配置条目的测试类型，这也是台账中 CM-6 合并处理的依据。

## 可审计性

合规档案记录处于审计历史之下：每次变更都会记录操作人、变更内容和变更时间。
