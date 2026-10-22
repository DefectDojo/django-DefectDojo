---
title: 附加文件
description: 在 DefectDojo OS 中为发现项、测试活动或测试上传屏幕截图、报告或其他支持性文件
audience: opensource
weight: 3
aliases:
- /zh-hans/triage_findings/findings_workflows/add_files/
---

您可以为**发现项**、**测试活动**或**测试**附加文件以提供支持性背景信息——例如概念验证截图、原始扫描器报告、网络拓扑图,或用于佐证结果的电子表格。

每个对象都保留自己独立的一组文件,单个对象最多可以附加**10 个文件**。

## 支持的文件类型

默认情况下,系统接受以下扩展名:

```
.txt  .pdf  .json  .xml  .csv  .yml  .png  .jpeg
.sarif  .xlsx  .doc  .html  .js  .nessus  .zip  .fpr
```

管理员可以通过 `DD_FILE_UPLOAD_TYPES` 环境变量修改此列表。上传扩展名不在列表中的文件会被表单拒绝。

图片文件(例如 `.png` 和 `.jpeg`)会以缩略图预览的形式呈现,其他类型的文件则以通用文件图标显示。无论哪种情况,点击文件都会下载该文件。

## 如何为发现项附加文件

1. 打开您要附加文件的发现项。
2. 打开操作菜单(发现项右上角的 **☰** 按钮),然后点击 **Manage Files**。

   ![发现项操作菜单中的 Manage Files 选项](images/OS_manage_files_menu.png)

3. 在 **Add files** 页面上,为文件输入一个**标题(Title)**,并从您的计算机中选择文件。您一次最多可以添加三个文件;如有需要,可以保存后返回继续添加。

   ![Manage Files 上传表单](images/OS_manage_files_form.png)

4. 点击 **Save**。

随后,该文件会列在发现项的 **Files** 面板中。图片文件会以缩略图形式显示:

![发现项上显示已附加截图的 Files 面板](images/OS_finding_files_panel.png)

## 为测试活动和测试附加文件

测试活动和测试使用相同的 **Manage Files** 工作流程:

- 在**测试活动**或**测试**的详情页面上,打开 **Files** 面板并点击其编辑(铅笔)按钮,然后按照与发现项相同的方式添加文件。

与发现项一样,图片附件会以缩略图形式呈现,其他类型的文件则显示通用文件图标。

## 查看和下载文件

已附加的文件会显示在对象详情页面的 **Files** 面板中。点击任意文件即可下载。访问会进行权限检查:用户必须对所属的发现项、测试活动或测试拥有**查看(view)**权限,才能下载其文件。

## 删除文件

要删除文件,请打开该对象的 **Manage Files**,勾选要删除文件下方的 **Delete** 复选框,然后点击 **Save**。
