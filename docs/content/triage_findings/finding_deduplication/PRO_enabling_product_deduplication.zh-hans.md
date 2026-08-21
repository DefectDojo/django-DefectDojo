---
title: 启用去重
description: 如何在产品或测试活动级别启用去重
weight: 2
audience: pro
aliases:
- /zh-hans/en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

去重功能可应用于整个产品\-范围，也可以更精细地限定到单个测试活动。

## 产品级去重

1. 导航到系统设置页面：侧边栏中的 **Settings \> System \> ⚙️ System Settings**（在仍使用旧版菜单布局的实例中为 **Settings \> Pro Settings \> System Settings**）。

![image](images/enabling_product-level_deduplication.png)

2. **去重与发现项设置（Deduplication and Finding Settings）**卡片位于**系统设置（System Settings）**页面的顶部。

![image](images/enabling_product-level_deduplication_2.png)

### 启用发现项去重

**启用发现项去重（Enable Finding Deduplication）**会为所有发现项开启去重算法。启用后，去重会在此后的每次导入时运行——DefectDojo 会将导入的发现项与目标产品中已有的发现项进行比较，并根据您的配置标记重复项。

### 删除重复发现项

**删除重复发现项（Delete Duplicate Findings）**与**最大重复数（Maximum Duplicates）**字段配合使用，用于限制 DefectDojo 保留的重复发现项数量。启用后，后台任务会定期清理多余的重复项，使每个原始发现项保留的重复项不超过所配置的**最大重复数**。最早的重复项会被优先删除。

## 测试活动级去重

您也可以不针对整个产品进行去重，而是将去重范围限定到单个测试活动。

### 打开测试活动表单

* **对于新的测试活动：** 打开侧边栏中的 **📥 Engagements** 子菜单，点击 **\+ New Engagement（新建测试活动）**。

![image](images/enabling_deduplication_within_an_engagement.png)

* **对于现有测试活动（从"所有测试活动"页面）：** 打开该测试活动的 **⋮** 菜单，选择 **Edit Engagement（编辑测试活动）**。

![image](images/enabling_deduplication_within_an_engagement_2.png)

* **对于现有测试活动（从测试活动页面）：** 打开页面右上角的 **⚙️ Gear** 菜单，选择 **Edit Engagement（编辑测试活动）**。

![image](images/enabling_deduplication_within_an_engagement_3.png)

### 填写测试活动表单

1. 在测试活动表单中，找到 ☐ **Isolate Deduplication from Other Engagements（与其他测试活动隔离去重）** 复选框。它位于 **Optional Fields \+（可选字段）** 面板上方。
2. 勾选此复选框，将去重范围限定到该测试活动。
3. 提交表单。

启用此选项后，该测试活动中的发现项只会与同一测试活动内的其他发现项进行去重比较。同一产品下其他测试活动中的发现项会被去重算法忽略。

![image](images/enabling_deduplication_within_an_engagement_4.png)
