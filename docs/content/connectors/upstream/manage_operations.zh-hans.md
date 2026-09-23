---
title: 管理操作
description: 查看连接器发现和同步操作的状态
aliases:
- /zh-hans/import_data/pro/connectors/manage_operations/
- /zh-hans/en/connecting_your_tools/connectors/manage_operations
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：上游连接器（Upstream Connectors）是 DefectDojo Pro 专属功能。</span>

上游连接器设置完成后，会定期运行两种操作：

* **发现（Discover）**会了解所连接工具的结构，并在 DefectDojo 中为任何未映射的数据创建记录；
* **同步（Sync）**会根据您的映射，从该工具导入新的发现项。

这两种操作都在连接器的操作页面上进行管理。该表格还会记录这些操作的历史运行情况，方便您确认连接器保持最新状态。

要访问某个连接器的操作页面，请打开您要处理的连接器的 **Manage Records \& Operations**，然后切换到 **</\> Operations From (tool)** 标签页。

![image](images/operations_discover.png)

**Manage Records \& Operations** 页面也可以用来处理记录（Records）；记录就是您所连接工具的各个 Product 映射。详情请参见[管理记录](../manage_records)。

## 操作页面

![image](images/operations_page.png)

操作页面表格中的每一条记录都对应一次操作事件，具有以下属性：

* **类型（Type）**表示该事件是**同步（Sync）**操作还是**发现（Discover）**操作。
* **状态（Status）**表示该事件是否成功运行。
* **触发方式（Trigger）**表示该事件是如何触发的——是自动运行的**计划（Scheduled）**操作，还是由 DefectDojo 用户触发的**手动（Manual）**操作？
* 每次操作的**开始与结束时间（Start \& End Time）**都会在此处记录，同时还会记录**持续时间（Duration）**。

## 发现操作

DefectDojo 连接器需要执行的第一步，是**发现（Discover）**您工具的环境，以了解您是如何组织扫描数据的。

举例来说，假设您有一个 BurpSuite 工具，被设置为扫描五个不同代码仓库中的漏洞。您的连接器会记录这种组织结构，并建立**记录（Records）**，帮助您将这些独立的代码仓库转化为 DefectDojo 的 Product/Engagement/Test 层级结构。

### 创建新记录

每次您的连接器运行**发现**操作时，都会查找新的**供应商等效产品（Vendor\-Equivalent\-Products，VEP）**。DefectDojo 会查看供应商工具的组织方式，并根据您所用工具的组织结构创建相应的 VEP **记录**。

![image](images/operations_discover_2.png)

### 手动运行发现

**发现**操作会定期自动运行，但也可以手动运行。如果您是第一次设置该连接器，可以点击 **Unmapped Records** 标题旁的 **Discover** 按钮。刷新页面后，您将看到初始的**记录**列表。

![image](images/operations_discover_3.png)

要进一步了解如何处理记录并设置到 Product 的映射，请参见我们的[管理记录](../manage_records)指南。

## 同步操作

DefectDojo 每天都会检查每一条**已映射记录（Mapped Record）**是否有新的扫描数据。随后 DefectDojo 会运行一次**重新导入（Reimport）**，将现有扫描数据的状态与新进的报告进行比较。

### 漏洞数据存储在哪里？

* DefectDojo 会在**记录映射（Record Mapping）**中指定的 Product 下创建一个 **Engagement**。该 Engagement 名为 **Global Connectors**。
* **Global Connectors** Engagement 会将与该 Product 关联的每个独立连接器作为一个 **Test** 进行跟踪。
* 在本次同步以及后续每次同步中，该 **Test** 都会将该工具发现的每一个漏洞存储为一个**发现项**。

### 同步如何处理新的漏洞数据

每次运行同步时，都会将最新的扫描数据与现有发现项列表进行比较，以识别变化。

* 如果检测到新的发现项，会将其作为新的发现项添加到该 Test 中。
* 如果有发现项未在最新扫描中被检测到，会在该 Test 中将其标记为“不活动（Inactive）”。

要进一步了解 Product、Engagement、Test 与发现项，请参见我们的 [Product 层级结构概览](/asset_modelling/os_hierarchy/product_hierarchy/)。

### 手动运行同步

要让 DefectDojo 在计划之外运行一次同步操作：

1. 前往您要使用的连接器的 **Manage Records \& Operations** 页面。在 **Upstream Connectors** 页面上，点击您要处理的连接器的 **Manage Configuration** 下拉菜单，并选择 **Manage Records \& Operations**。  
​
2. 在该页面上，点击 **Sync** 按钮。该按钮位于 **Mapped Records** 标题旁。

![image](images/operations_sync.png)
