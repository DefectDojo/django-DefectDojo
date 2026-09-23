---
title: Universal Importer 与 DefectDojo-CLI
description: 通过命令行将文件导入 DefectDojo
draft: false
weight: 2
audience: pro
aliases:
- /zh-hans/en/connecting_your_tools/external_tools
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注意：以下外部工具仅为 DefectDojo Pro 功能。除非连接到具有 DefectDojo Pro 许可证的实例，否则这些二进制文件将无法运行。</span>

## 关于外部工具

`defectdojo-cli` 和 `universal-importer` 是命令行工具，旨在简化发现项及相关对象的导入和重新导入流程，非常适合希望快速设置与 DefectDojo API 交互的用户。

DefectDojo-CLI 具有与 Universal Importer 相同的功能，此外还可以将发现项从 DefectDojo 导出为 JSON 或 CSV 格式。

## 安装

1. 从用户个人资料菜单中找到"外部工具"：

2. 从平台下载适用于您操作系统的相应二进制文件。

![image](images/external-tools.png)

3. 将下载的压缩包解压到您选择的目录中。您也可以选择将包含解压后二进制文件的目录添加到系统的 $PATH 中，以便重复使用。

**请注意，由于 DefectDojo-CLI 和 Universal Importer 来自身份不明的开发者，Macintosh 用户可能会被系统阻止运行。有关如何解除 Apple 阻止的说明，请参阅 [Apple 支持](https://support.apple.com/en-ca/guide/mac-help/mh40616/mac)。**

**Windows 用户：如果您收到"无法下载 - 检测到病毒"错误，禁用 Smartscreen 可能会解决此问题。否则，请使用其他浏览器从云端门户下载该工具。**

## 配置

Universal Importer 和 DefectDojo-CLI 可以通过标志、环境变量或配置文件进行配置。最重要的配置项是 API 令牌，必须将其设置为环境变量：

1. 将您的 API 密钥添加到环境变量中。
您可以从以下位置获取 API 密钥：`https://YOUR_INSTANCE.cloud.defectdojo.com/api/key-v2`

或者

通过 DefectDojo 用户界面
右上角的用户下拉菜单：

![image](images/api-token.png)

2. 设置 API 令牌的环境变量。

**对于 DefectDojo-CLI：**
	`export DD_CLI_API_TOKEN=YOUR_API_KEY`

**对于 Universal Importer：**
	`export DD_IMPORTER_DOJO_API_TOKEN=YOUR_API_KEY`

注意：在 Windows 上，请使用 `set` 而非 `export`。

### Windows：使用 PowerShell

1. 打开 PowerShell（按 Windows 键，然后搜索"PowerShell"）。
2. 设置环境变量：
   - **临时：**
     ```powershell
     $env:DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     $env:DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **永久：**
     ```powershell
     [Environment]::SetEnvironmentVariable("DD_IMPORTER_DOJO_API_TOKEN", "[VALUE_FROM_DEFECTDOJO_API]", "Machine")
     ```
3. 重新启动 PowerShell 会话。
4. 验证设置：
   ```powershell
   echo $env:DD_IMPORTER_DOJO_API_TOKEN
   echo $env:DD_IMPORTER_DEFECTDOJO_URL
   ```

### Windows：使用命令提示符（管理员账户）
1. 打开命令提示符（按 Windows 键，然后搜索"命令提示符"）。
2. 设置环境变量：
   - **临时：**
     ```cmd
     set DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     set DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```
   - **永久：**
     ```cmd
     setx DD_IMPORTER_DOJO_API_TOKEN = "[VALUE_FROM_DEFECTDOJO_API]"
     setx DD_IMPORTER_DEFECTDOJO_URL=”[e.g. http://localhost:8080/defectdojo]”
     ```

### 使用 Windows 设置（非管理员账户）
1. 按 `Win + I` 打开系统设置对话框。
2. 在搜索框中输入"environment"。
3. 选择"编辑账户的环境变量"。
4. 在"[用户名] 的用户变量"下，点击"新建…"按钮。
5. 设置变量：
   - **变量名：** `DD_IMPORTER_DOJO_API_TOKEN`
   - **变量值：** `[VALUE_FROM_DEFECTDOJO_API]`
6. 点击"确定"。
7. 对 DD_IMPORTER_DEFECTDOJO_URL 变量重复步骤 4 到 6
8. 重新启动任何已打开的命令窗口。
9. 验证设置：
   ```cmd
   echo %DD_IMPORTER_DOJO_API_TOKEN%
   echo %DD_IMPORTER_DEFECTDOJO_URL%
   ```

## DefectDojo-CLI

`defectdojo-cli` 可将扫描结果无缝集成到 DefectDojo 中，简化发现项及相关对象的导入和重新导入流程。该工具设计易用，支持多种端点，既可用于初始导入，也可用于后续重新导入 — 非常适合需要与 DefectDojo API 进行稳健、灵活交互的用户。DefectDojo-CLI 可以执行与 `universal-importer` 相同的功能，并额外提供发现项的导出功能。

### 命令

- [`import`](./#import)       将发现项导入 DefectDojo。
- [`reimport`](./#reimport)     将发现项重新导入 DefectDojo。
- [`export`](./#export)	将发现项从 DefectDojo 导出。
- [`interactive`](./#interactive)   启动交互模式，逐步配置导入和重新导入流程

### 全局选项

`--help, -h`
* 显示帮助

`--version, -v`
* 打印版本

#### CLI 格式设置

`--no-color`
* 禁用彩色输出。（默认值：false）`[$DD_CLI_NO_COLOR]`
`--no-emojis, --no-emoji`

* 禁用输出中的表情符号。（默认值：false）`[$DD_CLI_NO_EMOJIS]`

* `--verbose`
启用详细输出。（默认值：false）`[$DD_CLI_VERBOSE]`

### 导入

使用 import 命令将新发现项导入 DefectDojo。

#### 用法

```
defectdojo-cli [global options] import <required flags> [optional flags]
	or: defectdojo-cli [global options] import  --config ./config-file-path
	or: defectdojo-cli import [-h | --help]
	or: defectdojo-cli import example [subcommand options]
	or: defectdojo-cli import example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

`import` 可以通过两种方式导入发现项：

**按 ID：**
* 创建一个产品（或使用现有产品）
* 在产品内创建一个测试活动
* 在 engagement 参数中提供测试活动的 id

在此场景中，将在测试活动内创建一个新的测试。

**按名称：**

* 创建一个产品（或使用现有产品）
* 在产品内创建一个测试活动
* 提供 product-name
* 提供 engagement-name
* 可选择提供 product-type-name

在此场景中，DefectDojo 将根据提供的详细信息查找测试活动。

使用名称时，您可以通过设置 `auto-create-context=true` 让导入工具自动创建测试活动、产品和产品类型。
您可以使用 `deduplication-on-engagement` 将导入发现项的去重范围限制在新创建的测试活动内。


**导入基本语法：**
```
defectdojo-cli import [options]
```

#### **导入示例：**
```
defectdojo-cli import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### 命令
`example, x`
* 显示导入操作所需和可选标志的示例

#### 选项

`--active, -a`
* 决定在导入时是否将发现项强制设为活动或非活动状态。值为 True 时将发现项强制设为活动，值为 False 时将所有发现项强制设为非活动。如果未设置该值，则活动状态将依据传入的报告文件确定。（默认值：未设置） `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`
* 导入或重新导入时使用的 API 扫描配置对象的 ID。（默认值：0） `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* 如果设置为 true，则来自 --tag 选项的标签将应用于端点（默认值：false）
`[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* 如果设置为 true，则来自 --tag 选项的标签将应用于发现项（默认值：false） `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* 如果设置为 true，导入工具将自动创建测试活动、产品和产品类型（默认值：false） `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* 如果为 True，则导入时报告中不再存在的旧发现项将被关闭并标记为已缓解。如果已设置 Service，则仅关闭该 Service 的发现项。[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* 选择 --close-old-findings 是否应用于产品中**所有**同类型的发现项。默认情况下，此值为 false，即仅测试活动内同类型的旧发现项在范围内（并会被 Close Old Findings 关闭）。[$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* 如果设置为 true，导入工具会将导入发现项的去重范围限制在新创建的测试活动内。（默认值：false） `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* 要导入发现项的目标测试活动的 ID。（默认值：0） `[$DD_CLI_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* 要导入发现项的目标测试活动的名称。 `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* 决定应导入的最低严重程度级别。有效值为：Critical, High, Medium, Low, Info。（默认值："Info"） `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* 要导入发现项的目标产品的名称。 `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* 要导入发现项的目标产品类型的名称。 `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* 要导入的报告文件路径。（必填）。 `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* 该工具的扫描类型（必填）。 `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* 要应用于测试对象的任何标签 `[$DD_CLI_TAGS]`

`--test-name value, --tn value`
* 要导入发现项的目标测试的名称 — 默认为扫描类型的名称。 `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* 测试的版本。 `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* 决定导入时是否应将发现项设为已验证。值为 True 时将发现项强制设为已验证。如果未设置该值，则已验证状态将依据传入的报告文件确定。 `[$DD_CLI_VERIFIED]`

**设置：**

`--config value, -c value`
* 用于设置选项值的 TOML 配置文件路径。如果该选项同时在配置文件和 CLI 中设置，则以 CLI 中设置的值为准。 `[$DD_CLI_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* 要导入发现项的目标 DefectDojo 实例的 URL。（必填）。 `[$DD_CLI_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          在连接到指定的 DefectDojo 实例时忽略 TLS 验证错误。大多数用户不应启用此标志。（默认值：false） `[$DD_CLI_INSECURE_TLS]`

### 重新导入

使用 `reimport` 命令通过以下两种方式之一，用新报告中的发现项扩展现有测试：

按 ID：
- 创建一个产品（或使用现有产品）
- 在产品内创建一个测试活动
- 导入一份扫描报告并找到该测试的 id
- 在 test-id 参数中提供该 id

按名称：
- 创建一个产品（或使用现有产品）
- 在产品内创建一个测试活动
- 导入一份报告，该操作将创建一个测试
- 提供 product-name
- 提供 engagement-name
- 可选：提供 test-name

在此场景中，DefectDojo 将根据提供的详细信息查找测试。如果未提供 test-name，则会根据 scan-type 选择测试活动内最新的测试。

使用名称时，您可以通过设置 `auto-create-context=true` 让导入工具自动创建测试活动、产品和产品类型。
您可以使用 `deduplication-on-engagement` 将导入发现项的去重范围限制在新创建的测试活动内。

#### 用法

```
defectdojo-cli [global options] reimport <required flags> [optional flags]
   or: defectdojo-cli [global options] reimport  --config ./config-file-path
   or: defectdojo-cli reimport [-h | --help]
   or: defectdojo-cli reimport example [subcommand options]
   or: defectdojo-cli reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

#### **重新导入示例：**

```
defectdojo-cli reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### 命令

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### 选项

`--active, -a`
* 决定在导入时是否将发现项强制设为活动或非活动状态。值为 True 时将发现项强制设为活动，值为 False 时将所有发现项强制设为非活动。如果未设置该值，则活动状态将依据传入的报告文件确定。 `[$DD_CLI_ACTIVE]`

`--api-scan-configuration value, --asc value`

* 导入或重新导入时使用的 API 扫描配置对象的 ID。（默认值：0） `[$DD_CLI_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* 如果设置为 true，则来自 --tag 选项的标签将应用于端点（默认值：false） `[$DD_CLI_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* 如果设置为 true，则来自 --tag 选项的标签将应用于发现项（默认值：false） `[$DD_CLI_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* 如果设置为 true，导入工具将自动创建测试活动、产品和产品类型（默认值：false） `[$DD_CLI_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* 如果为 True，则导入时报告中不再存在的旧发现项将被关闭并标记为已缓解。如果已设置 Service，则仅关闭该 Service 的发现项。[$DD_CLI_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* 选择 --close-old-findings 是否应用于产品中**所有**同类型的发现项。默认情况下，此值为 false，即仅测试活动内同类型的旧发现项在范围内（并会被 Close Old Findings 关闭）。[$DD_CLI_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* 如果设置为 true，导入工具会将导入发现项的去重范围限制在新创建的测试活动内。（默认值：false） `[$DD_CLI_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`
* 要导入发现项的目标测试活动的名称。 `[$DD_CLI_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* 决定应导入的最低严重程度级别。有效值为：Critical, High, Medium, Low, Info。（默认值："Info"） `[$DD_CLI_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* 要导入发现项的目标产品的名称。 `[$DD_CLI_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* 要导入发现项的目标产品类型的名称。 `[$DD_CLI_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* 要导入的报告文件路径。（必填）。 `[$DD_CLI_REPORT_PATH]`

`--scan-type value, -s value`
* 该工具的扫描类型（必填）。 `[$DD_CLI_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* 要应用于测试对象的任何标签 `[$DD_CLI_TAGS]`

`--test-id value, --ti value`
* 要重新导入发现项的目标测试的 ID。（默认值：0） `[$DD_CLI_TEST_ID]`

`--test-name value, --tn value`
* 要导入发现项的目标测试的名称 — 默认为扫描类型的名称。 `[$DD_CLI_TEST_NAME]`

`--test-version value, -V value`
* 测试的版本。 `[$DD_CLI_TEST_VERSION]`

`--verified, -v`
* 决定导入时是否应将发现项设为已验证。值为 True 时将发现项强制设为已验证。如果未设置该值，则已验证状态将依据传入的报告文件确定。 `[$DD_CLI_VERIFIED]`

**设置：**

`--config value, -c value`
* 用于设置选项值的 TOML 配置文件路径。如果该选项同时在配置文件和 CLI 中设置，则以 CLI 中设置的值为准。 `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
* 要导入发现项的目标 DefectDojo 实例的 URL。（必填）。 `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* 在连接到指定的 DefectDojo 实例时忽略 TLS 验证错误。大多数用户不应启用此标志。（默认值：false） `[$DD_CLI_INSECURE_TLS]`

### 导出

#### 用法

```
defectdojo-cli export <required options> [optional options]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --defectdojo-url <https://YOUR_INSTANCE.cloud.defectdojo.com/> --json ./output_file_path.json --csv ./output_file_path.csv [optional filters]
	or: defectdojo-cli [global options] export --config ./config-file-path
	or: defectdojo-cli [global options] export --config ./config-file-path --json ./output_file_path.json
	or: defectdojo-cli [global options] export --config ./config-file-path --csv ./output_file_path.csv
	or: defectdojo-cli export [-h | --help]
	or: defectdojo-cli export example [subcommand options]
	or: defectdojo-cli export example [-h | --help]

>> The API token must be set in the environment variable `DD_CLI_API_TOKEN`.
```

要从 DefectDojo-CLI 导出发现项，您需要提供一个配置文件，其中包含说明您希望导出哪些发现项的详细信息。这与通过 API 调用 GET Findings 方法类似。

如需帮助，请使用 `defectdojo-cli export --help`。

#### **导出示例**

此示例指定了 URL、导出格式以及若干过滤参数，以创建发现项列表。

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
--json "./path/to/findings.json" \
--active "true" \
--created "Past 90 days"
```

#### 命令

`example, x`
* 显示导出操作所需和可选标志的示例

`help, h`
* 显示命令列表或某个命令的帮助信息

#### 选项

**发现项过滤器：**

`--active true|false, -a true|false`
* 按活动状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_ACTIVE]`

`--created value`
* 按创建日期筛选发现项。支持的值：None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_CREATED]`

`--cvssv3-score value`
* 按 CVSS v3 分数筛选发现项。（默认值：忽略） `[$DD_CLI_FINDINGS_FILTERS_CVSSV3_SCORE]`

`--cwe value`
* 按 CWE ID 筛选发现项。（默认值：忽略） `[$DD_CLI_FINDINGS_FILTERS_CWE]`

`--date value`
* 按日期筛选发现项。支持的值：None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_DATE]`

`--discovered-after value`
* 筛选在指定日期之后发现的发现项。格式：YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_AFTER]`

`--discovered-before value`
* 筛选在指定日期之前发现的发现项。格式：YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_BEFORE]`

`--discovered-on value`
* 按发现日期筛选发现项。格式：YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_DISCOVERED_ON]`

`--duplicate true|false`
* 按重复状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_DUPLICATE]`

`--engagement-ids value [ --engagement-ids value ]`
* 按测试活动 ID 筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。 `[$DD_CLI_FINDINGS_FILTERS_ENGAGEMENT]`

`--epss-percentile value`
* 按 EPSS 百分位数筛选发现项。（默认值：忽略） `[$DD_CLI_FINDINGS_FILTERS_EPSS_PERCENTILE]`

`--epss-score value`
* 按 EPSS 分数筛选发现项。（默认值：忽略） `[$DD_CLI_FINDINGS_FILTERS_EPSS_SCORE]`

`--false-positive true|false`
* 按误报状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_FALSE_POSITIVE]`

`--is-mitigated true|false`
* 按缓解状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_IS_MITIGATED]`

`--mitigated value`
* 按发现项被标记为已缓解的日期范围筛选。支持的值：None, Today, Past 7 days, Past 30 days, Past 90 days, Current month, Current year, Past year `[$DD_CLI_FINDINGS_FILTERS_MITIGATED]`

`--mitigated-after value`
* 筛选在指定日期之后被缓解的发现项。格式：YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_AFTER]`

`--mitigated-before value`
* 筛选在指定日期之前被缓解的发现项。格式：YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BEFORE]`

`--mitigated-by-ids value [ --mitigated-by-ids value ]`
* 按 mitigated_by 用户 ID 筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。可与 --mitigated-by-names 结合使用。 `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_IDS]`

`--mitigated-by-names value [ --mitigated-by-names value ]`
* 按 mitigated_by 用户名筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。可与 --mitigated-by-ids 结合使用。 `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_BY_NAMES]`

`--mitigated-on value`
* 按缓解日期筛选发现项。格式：YYYY-MM-DD `[$DD_CLI_FINDINGS_FILTERS_MITIGATED_ON]`

`--not-tags value [ --not-tags value ]`
* 按不应存在的标签筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。 `[$DD_CLI_FINDINGS_FILTERS_NOT_TAGS]`

`--out-of-scope true|false`
* 按超出范围或在范围内状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SCOPE]`

`--out-of-sla true|false`
* 按超出或未超出 SLA 状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_OUT_OF_SLA]`

`--product-name value`
* 按产品名称筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME]`

`--product-name-contains value`
* 按产品名称包含的字符串筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_NAME_CONTAINS]`

`--product-type-ids value [ --product-type-ids value ]`
* 按产品类型 ID 筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。可与 --product-type-names 结合使用 `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_IDS]`

`--product-type-names value [ --product-type-names value ]`
* 按产品类型名称筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。可与 --product-type-ids 结合使用 `[$DD_CLI_FINDINGS_FILTERS_PRODUCT_TYPE_NAMES]`

`--risk-accepted true|false`
* 按风险已接受状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_RISK_ACCEPTED]`

`--severity value [ --severity value ]`
* 按严重程度筛选发现项。有效值为：Critical, High, Medium, Low, Info。此标志可多次使用，也可以以逗号分隔的列表形式使用。 `[$DD_CLI_FINDINGS_FILTERS_SEVERITY]`

`--tags value [ --tags value ]`
* 按应存在的标签筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。 `[$DD_CLI_FINDINGS_FILTERS_TAGS]`

`--test-id value`
* 按测试 ID 筛选发现项。（默认值：忽略） `[$DD_CLI_FINDINGS_FILTERS_TEST_ID]`

`--title-contains value`
* 按标题中包含给定字符串筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_TITLE_CONTAINS]`

`--under-review true|false`
* 按审核中状态筛选发现项。 `[$DD_CLI_FINDINGS_FILTERS_UNDER_REVIEW]`

`--verified true|false`
* 按已验证状态筛选发现项。（默认值：忽略） `[$DD_CLI_FINDINGS_FILTERS_VERIFIED]`

`--vulnerability-id value [ --vulnerability-id value ]`
* 按漏洞 ID 筛选发现项。此标志可多次使用，也可以以逗号分隔的列表形式使用。 `[$DD_CLI_FINDINGS_FILTERS_VULNERABILITY_ID]`

**发现项输出**

`--csv value`
* 写入发现项 CSV 文件的路径。 `[$DD_CLI_FINDINGS_OUTPUT_CSV_PATH_FILE]`

`--json value`  写入发现项 JSON 文件的路径。 `[$DD_CLI_FINDINGS_OUTPUT_JSON_PATH_FILE]`

**设置**

`--config value, -c value`
用于设置选项值的 TOML 配置文件路径。如果该选项同时在配置文件和 CLI 中设置，则以 CLI 中设置的值为准。 `[$DD_CLI_CONFIG_FILE]`

`--defectdojo-url value, -u value`
要导入发现项的目标 DefectDojo 实例的 URL。（必填）。 `[$DD_CLI_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
在连接到指定的 DefectDojo 实例时忽略 TLS 验证错误。大多数用户不应启用此标志。（默认值：false） `[$DD_CLI_INSECURE_TLS]`

#### 导出示例：

```
defectdojo-cli export \
--defectdojo-url "https://your-dojo-instance.cloud.defectdojo.com/"
```

### 交互模式

交互模式允许您逐步配置导入和重新导入流程。

#### 用法

```
defectdojo-cli interactive
	or: defectdojo-cli interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: defectdojo-cli interactive [-h | --help]
```

#### 选项

`--skip-intro `
* 跳过介绍屏幕（默认值：false）

`--no-full-screen`
* 禁用全屏模式（默认值：false）

`--log-path value`
* 日志文件的路径

`--help, -h`
* 显示帮助

## Universal Importer

`universal-importer` 可将扫描结果无缝集成到 DefectDojo 中，简化发现项及相关对象的导入和重新导入流程。该工具设计易用，支持多种端点，既可用于初始导入，也可用于后续重新导入 — 非常适合需要与 DefectDojo API 进行稳健、灵活交互的用户。

虽然与 DefectDojo-CLI 类似，但 Universal Importer 没有导出功能，且环境变量的编码方式不同。

### 命令

- [`import`](./#import-1)       将发现项导入 DefectDojo。
- [`reimport`](./#reimport-1)     将发现项重新导入 DefectDojo。
- [`interactive`](./#interactive-1)   启动交互模式，逐步配置导入和重新导入流程

### 全局选项

`--help, -h`
* 显示帮助

`--version, -v`
* 打印版本

#### CLI 格式设置

`--no-color`
* 禁用彩色输出。（默认值：false） `[$DD_IMPORTER_NO_COLOR]`

`--no-emojis, --no-emoji`
* 禁用输出中的表情符号。（默认值：false） `[$DD_IMPORTER_NO_EMOJIS]`

`--verbose`
* 启用详细输出。（默认值：false） `[$DD_IMPORTER_VERBOSE]`

### 导入

使用 import 命令将新发现项导入 DefectDojo。

#### 用法

```
universal-importer [global options] import <required flags> [optional flags]
	or: universal-importer [global options] import  --config ./config-file-path
	or: universal-importer import [-h | --help]
	or: universal-importer import example [subcommand options]
	or: universal-importer import example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

`import` 可以通过两种方式导入发现项：

**按 ID：**
* 创建一个产品（或使用现有产品）
* 在产品内创建一个测试活动
* 在 engagement 参数中提供测试活动的 id

在此场景中，将在测试活动内创建一个新的测试。

**按名称：**
* 创建一个产品（或使用现有产品）
* 在产品内创建一个测试活动
* 提供 product-name
* 提供 engagement-name
* 可选择提供 product-type-name

在此场景中，DefectDojo 将根据提供的详细信息查找测试活动。

使用名称时，您可以通过设置 `auto-create-context=true` 让导入工具自动创建测试活动、产品和产品类型。
您可以使用 `deduplication-on-engagement` 将导入发现项的去重范围限制在新创建的测试活动内。


**导入基本语法：**

```
universal-importer import [options]
```

#### **导入示例：**

```
universal-importer import \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "burp scan" \
--report-path "./examples/burp_findings.xml" \
--product-name "dev" \
--engagement-name "dev" \
--product-type-name "Research and Development" \
--test-name "burp-test-dev" \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "burp" --tag "test-dev" \
--test-version "0.0.1" \
--auto-create-context
```

#### 命令

`example, x`
* 显示导入操作所需和可选标志的示例

#### 选项

`--active, -a`
* 决定在导入时是否将发现项强制设为活动或非活动状态。值为 True 时将发现项强制设为活动，值为 False 时将所有发现项强制设为非活动。如果未设置该值，则活动状态将依据传入的报告文件确定。 `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* 导入或重新导入时使用的 API 扫描配置对象的 ID。（默认值：0） `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* 如果设置为 true，则来自 --tag 选项的标签将应用于端点（默认值：false）
`[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* 如果设置为 true，则来自 --tag 选项的标签将应用于发现项（默认值：false） `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* 如果设置为 true，导入工具将自动创建测试活动、产品和产品类型（默认值：false） `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* 如果为 True，则导入时报告中不再存在的旧发现项将被关闭并标记为已缓解。如果已设置 Service，则仅关闭该 Service 的发现项。[$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* 选择 --close-old-findings 是否应用于产品中**所有**同类型的发现项。默认情况下，此值为 false，即仅测试活动内同类型的旧发现项在范围内（并会被 Close Old Findings 关闭）。[$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* 如果设置为 true，导入工具会将导入发现项的去重范围限制在新创建的测试活动内。（默认值：false） `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-id value, --ei value`
* 要导入发现项的目标测试活动的 ID。（默认值：0） `[$DD_IMPORTER_ENGAGEMENT_ID]`

`--engagement-name value, -e value`
* 要导入发现项的目标测试活动的名称。 `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* 决定应导入的最低严重程度级别。有效值为：Critical, High, Medium, Low, Info。（默认值："Info"） `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* 要导入发现项的目标产品的名称。 `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* 要导入发现项的目标产品类型的名称。 `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* 要导入的报告文件路径。（必填）。 `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* 该工具的扫描类型（必填）。 `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* 要应用于测试对象的任何标签 `[$DD_IMPORTER_TAGS]`

`--test-name value, --tn value`
* 要导入发现项的目标测试的名称 — 默认为扫描类型的名称。 `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* 测试的版本。 `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* 决定导入时是否应将发现项设为已验证。值为 True 时将发现项强制设为已验证。如果未设置该值，则已验证状态将依据传入的报告文件确定。 `[$DD_IMPORTER_VERIFIED]`

**设置：**

`--config value, -c value`
* 用于设置选项值的 TOML 配置文件路径。如果该选项同时在配置文件和 CLI 中设置，则以 CLI 中设置的值为准。 `[$DD_IMPORTER_CONFIG_FILE]`
`--defectdojo-url value, -u value`
* 要导入发现项的目标 DefectDojo 实例的 URL。（必填）。 `[$DD_IMPORTER_DEFECTDOJO_URL]`
* --insecure-tls, --no-tls          在连接到指定的 DefectDojo 实例时忽略 TLS 验证错误。大多数用户不应启用此标志。（默认值：false） `[$DD_IMPORTER_INSECURE_TLS]`

### 重新导入

使用 `reimport` 命令通过以下两种方式之一，用新报告中的发现项扩展现有测试：

By ID:
- 创建一个产品（或使用现有产品）
- 在产品内创建一个测试活动
- 导入一份扫描报告并找到该测试的 id
- 在 test-id 参数中提供该 id

By Names:
- 创建一个产品（或使用现有产品）
- 在产品内创建一个测试活动
- 导入一份报告，该操作将创建一个测试
- 提供 product-name
- 提供 engagement-name
- 可选：提供 test-name

在此场景中，DefectDojo 将根据提供的详细信息查找测试。如果未提供 test-name，则会根据 scan-type 选择测试活动内最新的测试。

使用名称时，您可以通过设置 `auto-create-context=true` 让导入工具自动创建测试活动、产品和产品类型。
您可以使用 `deduplication-on-engagement` 将导入发现项的去重范围限制在新创建的测试活动内。

#### 用法

```
universal-importer [global options] reimport <required flags> [optional flags]
   or: universal-importer [global options] reimport  --config ./config-file-path
   or: universal-importer reimport [-h | --help]
   or: universal-importer reimport example [subcommand options]
   or: universal-importer reimport example [-h | --help]

>> The API token must be set in the environment variable `DD_IMPORTER_DOJO_API_TOKEN`.
```

#### **重新导入示例：**

```
universal-importer reimport \
--defectdojo-url "https://YOUR_INSTANCE.cloud.defectdojo.com/" \
--scan-type "Nancy Scan" \
--report-path "./examples/nancy_findings.json" \
--test-id 11 \
--verified \
--active \
--minimum-severity "info" \
--tag "dev" --tag "tools" --tag "nancy" --tag "test-dev" \
--test-version "1.0" \
--auto-create-context
```

#### 命令

```
example, x  Shows an example of required and optional flags for reimport operation
```

#### 选项

`--active, -a`
* 决定在导入时是否将发现项强制设为活动或非活动状态。值为 True 时将发现项强制设为活动，值为 False 时将所有发现项强制设为非活动。如果未设置该值，则活动状态将依据传入的报告文件确定。 `[$DD_IMPORTER_ACTIVE]`

`--api-scan-configuration value, --asc value`
* 导入或重新导入时使用的 API 扫描配置对象的 ID。（默认值：0） `[$DD_IMPORTER_API_SCAN_CONFIGURATION]`

`--apply-tags-endpoints, --te`
* 如果设置为 true，则来自 --tag 选项的标签将应用于端点（默认值：false） `[$DD_IMPORTER_APPLY_TAGS_ENDPOINTS]`

`--apply-tags-findings, --tf`
* 如果设置为 true，则来自 --tag 选项的标签将应用于发现项（默认值：false） `[$DD_IMPORTER_APPLY_TAGS_FINDINGS]`

`--auto-create-context, --acc`
* 如果设置为 true，导入工具将自动创建测试活动、产品和产品类型（默认值：false） `[$DD_IMPORTER_AUTO_CREATE_CONTEXT]`

`--close-old-findings, --cof`
* 如果为 True，则导入时报告中不再存在的旧发现项将被关闭并标记为已缓解。如果已设置 Service，则仅关闭该 Service 的发现项。[$DD_IMPORTER_CLOSE_OLD_FINDINGS]

`--close-old-findings-product-scope, --cofps`
* 选择 --close-old-findings 是否应用于产品中**所有**同类型的发现项。默认情况下，此值为 false，即仅测试活动内同类型的旧发现项在范围内（并会被 Close Old Findings 关闭）。[$DD_IMPORTER_CLOSE_OLD_FINDINGS_PRODUCT_SCOPE]

`--deduplication-on-engagement, --doe`
* 如果设置为 true，导入工具会将导入发现项的去重范围限制在新创建的测试活动内。（默认值：false） `[$DD_IMPORTER_DEDUPLICATION_ON_ENGAGEMENT]`

`--engagement-name value, -e value`
* 要导入发现项的目标测试活动的名称。 `[$DD_IMPORTER_ENGAGEMENT_NAME]`

`--minimum-severity value, --ms value`
* 决定应导入的最低严重程度级别。有效值为：Critical, High, Medium, Low, Info。（默认值："Info"） `[$DD_IMPORTER_MINIMUM_SEVERITY]`

`--product-name value, -p value`
* 要导入发现项的目标产品的名称。 `[$DD_IMPORTER_PRODUCT_NAME]`

`--product-type-name value, --pt value`
* 要导入发现项的目标产品类型的名称。 `[$DD_IMPORTER_PRODUCT_TYPE_NAME]`

`--report-path value, -r value`
* 要导入的报告文件路径。（必填）。 `[$DD_IMPORTER_REPORT_PATH]`

`--scan-type value, -s value`
* 该工具的扫描类型（必填）。 `[$DD_IMPORTER_SCAN_TYPE]`

`--tag value, -t value [ --tag value, -t value ]`
* 要应用于测试对象的任何标签 `[$DD_IMPORTER_TAGS]`

`--test-id value, --ti value`
* 要重新导入发现项的目标测试的 ID。（默认值：0） `[$DD_IMPORTER_TEST_ID]`

`--test-name value, --tn value`
* 要导入发现项的目标测试的名称 — 默认为扫描类型的名称。 `[$DD_IMPORTER_TEST_NAME]`

`--test-version value, -V value`
* 测试的版本。 `[$DD_IMPORTER_TEST_VERSION]`

`--verified, -v`
* 决定导入时是否应将发现项设为已验证。值为 True 时将发现项强制设为已验证。如果未设置该值，则已验证状态将依据传入的报告文件确定。（默认值：未设置） `[$DD_IMPORTER_VERIFIED]`

**设置：**

`--config value, -c value`
* 用于设置选项值的 TOML 配置文件路径。如果该选项同时在配置文件和 CLI 中设置，则以 CLI 中设置的值为准。 `[$DD_IMPORTER_CONFIG_FILE]`

`--defectdojo-url value, -u value`
* 要导入发现项的目标 DefectDojo 实例的 URL。（必填）。 `[$DD_IMPORTER_DEFECTDOJO_URL]`

`--insecure-tls, --no-tls`
* 在连接到指定的 DefectDojo 实例时忽略 TLS 验证错误。大多数用户不应启用此标志。（默认值：false） `[$DD_IMPORTER_INSECURE_TLS]`

### 交互模式
交互模式允许您逐步配置导入和重新导入流程。

#### 用法

```
universal-importer interactive
	or: universal-importer interactive  [--skip-intro] [--no-full-screen] [--log-path]
	or: universal-importer interactive [-h | --help]
```

#### 选项

`--skip-intro `
* 跳过介绍屏幕（默认值：false）

`--no-full-screen`
* 禁用全屏模式（默认值：false）
`--log-path value`
* 日志文件的路径
`--help, -h`
* 显示帮助


## 故障排查

如果您在使用这些工具时遇到任何问题，请检查以下事项：
- 确保您使用的二进制文件与您的操作系统和 CPU 架构相匹配。
- 验证 API 密钥是否已在环境变量中正确设置。
- 检查 DefectDojo URL 是否正确且可访问。
- 导入时，确认报告文件存在，且格式受指定扫描类型支持。您可以在我们的[受支持工具列表](/supported_tools)中查看 DefectDojo 支持的扫描器。
