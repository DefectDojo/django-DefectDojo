---
title: DefectDojo API v2
description: DefectDojo 的 API 可让您自动执行任务，例如在 CI/CD 流水线中上传扫描报告。
draft: false
weight: 2
aliases:
- /zh-hans/en/api/api-v2-docs
---

DefectDojo 的 API 使用 [Django Rest
Framework](http://www.django-rest-framework.org/) 构建。每个端点的文档
在每个 DefectDojo 安装实例中都可以通过
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) 获取，也可以通过页眉中用户下拉菜单里的 API v2
Docs 链接访问。

![image](images/api_v2_1.png)

该文档使用 [drf-spectacular](https://drf-spectacular.readthedocs.io/) 在 [`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/) 生成，并且
是可交互的。在 API v2 文档顶部有一个链接，可用于生成 OpenAPI v3 规范。

要与该文档进行交互，需要提供一个有效的 Authorization 请求头
值。访问 `/api/key-v2` 页面以生成您的
API 密钥（`Token <api_key>`），然后复制所提供的请求头值。

![image](images/api_v2_2.png)

每个部分都允许您调用 API，并查看请求
URL、响应正文（Response Body）、响应代码（Response Code）以及响应头（Response Headers）。

![image](images/api_v2_3.png)

如果您已登录到 Defect Dojo 网页界面，则无需提供授权令牌。

## Authentication

该 API 使用带有 API 密钥的请求头身份验证方式。请求头的
格式应为：:

    Authorization: Token <api.key>

例如：:

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Alternative authentication method

如果您为用户使用[某种替代身份验证方法](/admin/sso/)，您可能会希望禁用 DefectDojo API 令牌，因为它可能绕过您的身份验证机制。\
可以通过将环境变量 `DD_API_TOKENS_ENABLED` 设置为 `False` 来禁用 DefectDojo API 令牌的使用。
也可以仅通过将 `DD_API_TOKEN_AUTH_ENDPOINT_ENABLED` 设置为 `False` 来禁用 `api/v2/api-token-auth/` 端点。

## Sample Code

以下是一些针对
`/users` 端点的简单 python 示例及其运行结果：:

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

此代码将返回 DefectDojo 中定义的所有用户列表。
json 对象结果如下所示：:

{{< highlight json >}}
    [
        {
          "first_name": "Tyagi",
          "id": 22,
          "last_login": "2019-06-18T08:05:51.925743",
          "last_name": "Paz",
          "username": "dev7958"
        },
        {
          "first_name": "saurabh",
          "id": 31,
          "last_login": "2019-06-06T11:44:32.533035",
          "last_name": "",
          "username": "saurabh.paz"
        }
    ]
{{< /highlight >}}

下面是另一个针对 `/users` 端点的示例，这
次我们将结果过滤为仅包含用户
名中包含 `jay` 的用户：

{{< highlight python >}}
import requests

url = 'http://127.0.0.1:8000/api/v2/users/?username__contains=jay'
headers = {'content-type': 'application/json',
            'Authorization': 'Token c8572a5adf107a693aa6c72584da31f4d1f1dcff'}
r = requests.get(url, headers=headers, verify=True) # set verify to False if ssl cert is self-signed

for key, value in r.__dict__.items():
  print(f"'{key}': '{value}'")
  print('------------------')
{{< /highlight >}}

json 对象结果为：:

{{< highlight json >}}
[
    {
        "first_name": "Jay",
        "id": 22,
        "last_login": "2015-10-28T08:05:51.925743",
        "last_name": "Paz",
        "username": "jay7958"
    },
    {
        "first_name": "",
        "id": 31,
        "last_login": "2015-10-13T11:44:32.533035",
        "last_name": "",
        "username": "jay.paz"
    }
]
{{< /highlight >}}

更多示例和技巧请参阅 [Django Rest Framework\'s documentation on interacting with an
API](https://www.django-rest-framework.org/)。

## Manually calling the API

可以使用 Postman 之类的工具来测试该 API。

导入扫描结果的示例：

-   动词：POST
-   URI：<http://localhost:8080/api/v2/import-scan/>
-   Headers 选项卡：

    添加身份验证请求头
    :   -   Key：Authorization
        -   Value：Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   Body 选项卡

    -   选择 \"form-data\"，点击 \"bulk edit\"。ZAP 扫描示例：

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   Body 选项卡

       -   点击 \"Key-value\" 编辑
       -   添加一个类型为 \"file\" 的 \"file\" 参数。这将触发
            用于发送文件内容的多部分表单数据
       -   浏览并选择要上传的文件

-   点击发送

## Clients / API Wrappers

| Wrapper                      | Status                   | Notes |
| -----------------------------| ------------------------| ------------------------|
| [Specific python wrapper](https://github.com/DefectDojo/defectdojo_api)      | working (2021-01-21)    | API 封装库，包含用于持续 CI/CD 上传的脚本。在最新 API 功能方面稍有滞后，因为我们计划对该 API 封装库进行改版 |
| [Openapi python wrapper](https://github.com/alles-klar/defectdojo-api-v2-client)       | | 目前仅是概念验证，我们由此发现 OpenAPI 规范尚不完善 |
| [Java library](https://github.com/secureCodeBox/defectdojo-client-java)                 | working (2021-08-30)    | 由 [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox) 的热心人士创建 |
| [Image using the Java library](https://github.com/SDA-SE/defectdojo-client) | working (2021-08-30)    | |
| [.Net/C# library](https://www.nuget.org/packages/DefectDojo.Api/)              | working (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | working (2021-08-24)    | dd-import 并非严格意义上的 API 封装库，它提供了一些便捷功能，使从 CI/CD 流水线导入发现项和语言数据变得更容易。 |

部分 API 封装库包含相当多的逻辑，用于简化 CI/CD 环境中的扫描和导入操作。我们正在通过让 DefectDojo API 变得更智能，来简化这一点（这样 API 封装库/脚本就可以变得更简单）。

## API Notes

### Import / Reimport

**重新导入（Reimport）** 实际上是最容易上手的方式，因为它会在需要时即时创建各类实体，并自动检测这是首次上传还是重复上传。

## Import
通过 API 进行导入是通过 [import-scan](https://demo.defectdojo.org/api/v2/doc/) 端点完成的。

如[产品层级结构](/asset_modelling/os_hierarchy/product_hierarchy/)中所述，测试（Test）创建在测试活动（Engagement）内部，测试活动创建在产品（Product）内部，产品创建在产品类型（Product Type）内部。

可以通过在 API 请求中指定这些实体的名称来执行导入：


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
}
```

当 `auto_create_context` 为 `True` 时，将在需要时创建产品、测试活动和环境。请确保您的用户拥有足够的[权限](/admin/user_management/about_perms_and_roles/)来执行此操作。

导入扫描的经典方式是改为指定测试活动的 ID：

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "engagement": 123,
}
```

## Reimport
通过 API 进行重新导入是通过 [reimport-scan](https://demo.defectdojo.org/api/v2/doc/) 端点完成的。

可以通过在 API 请求中指定这些实体的名称来执行重新导入：


```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test_title": 'Manual ZAP Scan by John',
    "product_type_name": 'Good Products',
    "product_name": 'My little product',
    "engagement_name": 'Important import',
    "auto_create_context": True,
    "do_not_reactivate": False,
}
```

当 `auto_create_context` 为 `True` 时，如果产品类型、产品和测试活动尚不存在，则会创建它们。请确保您的用户拥有足够的[权限](/admin/user_management/about_perms_and_roles/)来创建产品/产品类型。

当 `do_not_reactivate` 为 `True` 时，导入/重新导入将忽略已上传的活动发现项，不会重新激活先前已关闭的发现项，但仍会创建新的发现项（如果存在的话）。您会在该发现项上看到一条备注，说明它因此原因而未被重新激活。

重新导入将自动选择所提供测试活动中满足所提供 `scan_type`（以及可选提供的 `test_title`）条件的最新测试。

如果找不到现有测试，重新导入端点将使用导入功能，将所提供的报告导入到一个新的测试中。这意味着使用该 API 的（CI/CD）脚本无需知道某个测试是否已经存在，也无需知道这是否是该产品/测试活动的首次上传。

重新导入扫描的经典方式是改为指定测试的 ID：

```JSON
{
    "minimum_severity": 'Info',
    "active": True,
    "verified": True,
    "scan_type": 'ZAP Scan',
    "test": 123,
}
```

## Generating Reports

DefectDojo 可以通过 API 生成 **JSON**、**HTML**、**CSV** 或 **Excel** 格式的发现项报告。

报告是通过向 `generate_report/` 操作发送 `POST` 请求生成的。findings 端点会针对您整个实例生成报告，而大多数其他对象则提供针对单个对象的操作：

| Endpoint | Scope |
|---|---|
| `POST /api/v2/findings/generate_report/` | 您有权查看的所有发现项 |
| `POST /api/v2/products/{id}/generate_report/` | 单个产品 |
| `POST /api/v2/engagements/{id}/generate_report/` | 单个测试活动 |
| `POST /api/v2/tests/{id}/generate_report/` | 单个测试 |
| `POST /api/v2/product_types/{id}/generate_report/` | 单个产品类型 |
| `POST /api/v2/endpoints/{id}/generate_report/` | 单个端点 |

Pro 版的对象别名提供相同的操作：`/api/v2/assets/{id}/generate_report/`、`/api/v2/organizations/{id}/generate_report/` 以及 `/api/v2/location/{id}/generate_report/`。

### Request options

所有字段均为可选 — 提交空请求体（`{}`）将返回一份 JSON 报告。

| Field | Type | Default | Description |
|---|---|---|---|
| `report_type` | string | `JSON` | 取值为 `JSON`、`HTML`、`CSV`、`Excel` 之一。 |
| `include_finding_notes` | boolean | `false` | 包含每个发现项的备注。 |
| `include_finding_images` | boolean | `false` | 包含发现项所附带的图片。 |
| `include_executive_summary` | boolean | `false` | 包含执行摘要部分。 |
| `include_table_of_contents` | boolean | `false` | 包含目录。 |

不受支持的 `report_type`（例如 `PDF`）会返回 `400 Bad Request`，并在 `report_type` 字段上给出错误提示。

### Example

生成一份包含您可查看的所有发现项的 CSV 报告，并将其保存到文件中：

```bash
curl -X POST \
  -H "Authorization: Token <your-api-token>" \
  -H "Content-Type: application/json" \
  -d '{"report_type": "CSV"}' \
  https://<your-instance>/api/v2/findings/generate_report/ \
  -o findings.csv
```

### Response formats

| `report_type` | Content type | Response |
|---|---|---|
| `JSON` (default) | `application/json` | 响应中包含报告正文 |
| `HTML` | `text/html` | 渲染后的报告页面 |
| `CSV` | `text/csv` | 文件附件 |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `.xlsx` 文件附件 |

CSV 和 Excel 是作为带有 `Content-Disposition` 请求头的文件附件返回的，而不是作为 JSON 正文返回。文件名来源于生成报告所基于的对象 — 例如 `product_1_findings.csv` 或 `test_42_findings.xlsx`。`/findings/generate_report/` 端点不限定于单个对象，因此其下载文件名固定为 `findings.csv` 和 `findings.xlsx`。

### Notes and limitations

* `include_*` 选项仅影响 **JSON** 和 **HTML** 报告。**CSV** 和 **Excel** 导出始终包含发现项行数据。
* 生成报告需要对相关对象拥有**查看（view）**权限，报告中也只会包含您有权查看的发现项。
* **标准的查询参数过滤器不适用于此操作。** 与 `GET /api/v2/findings/` 不同，`generate_report/` 操作不会应用发现项过滤器，因此像 `POST /api/v2/findings/generate_report/?severity=High` 这样的请求，仍会报告您可查看的全部发现项。若要缩小报告范围，请改为针对特定产品、测试活动或测试生成报告。

## Asynchronous Deletion Behavior

DefectDojo 中的删除操作（无论通过 API 还是 UI）都由 Celery 后台工作进程**异步**处理。当您删除一个测试活动、测试或其他对象时，API 或 UI 会立即返回成功响应，但实际的删除操作会在后台运行。

这意味着：
- 在删除操作确认之后的一段时间内，对象可能仍会出现在查询结果中。
- 级联删除（例如删除一个测试活动同时也会删除其测试和发现项）会作为一系列后台任务链进行处理。子对象会按依赖顺序被移除：先是发现项，然后是测试，最后是测试活动。
- 对于包含大量发现项的大型测试活动，此过程可能需要几分钟才能完成。

无需构建自定义脚本来按依赖顺序删除对象。对某个测试活动发出的单个 `DELETE` 请求，会自动级联到其所有子对象。只需留出足够的时间让后台任务完成即可。

## API Pagination Limits

DefectDojo Pro 对每个 API 请求强制实施最多 **250** 条结果的分页大小限制。将 `limit` 设置为高于 250 的值，可能会因查询超时而导致 HTTP 502 错误。

开源版 DefectDojo 实例在分页大小非常大时，也可能因数据集大小和服务器资源的不同而出现超时。

对于较大的结果集，请使用 50-250 之间的分页大小，并在各分页请求之间加入短暂延迟，以避免使工作进程池达到饱和。

## Large-Scale Import Best Practices

在大规模导入扫描结果时（例如包含数千个组件的 SBOM 流水线），请考虑以下几点：

- **对较大的负载使用 `background_import=true`。** 同步导入会在导入期间占用一个 uwsgi 工作进程，这可能会降低所有用户的性能。
- **尽可能将每次导入的负载大小控制在 1 MB 以下。** 将较大的 SBOM 按产品或组件分组拆分为多个较小的文件。
- **在连续的 API 调用之间加入延迟**，以避免工作进程池耗尽而引发 HTTP 502 错误。
- **对定期性的扫描使用重新导入（Reimport）**（`/api/v2/reimport-scan/`）来更新现有发现项，而不是创建重复项。

## Background import responses (API: `background_import`)

后台导入会在上传的报告解析完成后立即返回，此时尚未写入任何
发现项。因此其响应描述的是*已计划*的工作，其结构也
与同步导入不同。只要 `background_import` 为 `true`，或者
`api_async_import` 系统设置为所有导入都启用了该行为，这一点就适用于 `/api/v2/import-scan/` 和
`/api/v2/reimport-scan/`。

后台响应包含：

- `background_import` — `true`。这是用于分支判断的字段。
- `status` — 响应生成那一刻测试所处的生命周期状态：
  `Processing`、`Post Processing - Deduplication`、
  `Post Processing - False Positive History`、`Processed` 或 `Failed`。
- `findings_parsed` — 从报告中解析出的发现项数量。这是一个解析
  计数，而非创建计数：去重逻辑以及您所提供的导入选项，将决定
  最终实际写入多少条发现项。
- `test_id`（以及 `engagement_id`、`product_id`、`product_type_id`）— 用于
  轮询的标识符。
- `message` — 以文字形式呈现与 `status` 和 `findings_parsed` 相同的信息。请优先使用
  结构化字段。

它**不**包含 `statistics`，也不包含 `deduplication_complete`。
这些键是缺失而非为零，因为此时尚未写入任何发现项，
若报告为零则会错误地描述该次导入。若客户端无条件读取
`response["statistics"]`，在遇到后台导入时会失败 — 请先读取
`background_import` 字段，或仅在同步路径中使用 `statistics`。

要跟踪某次后台导入直至完成，请轮询该测试：

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

重复执行该 `GET` 请求，直到 `status` 变为 `Processed`（导入已完成，此时测试的
发现项计数才具有意义）或 `Failed`（导入未能完成）。在
导入进行期间，`processing` 为 `true`，`status` 会报告当前所处的阶段。请在
每次轮询之间间隔几秒钟；较大的报告在后处理阶段可能会耗费数分钟。

同步导入（省略 `background_import` 或将其设为 `false`）保持不变：它会
在发现项写入完成后返回，包含 `statistics`，且不包含 `status`
或 `findings_parsed`。

## Using the Scan Completion Date (API: `scan_date`) field

DefectDojo 支持大量的扫描器报告格式，但并非所有报告都包含用户最看重的
信息。`scan_date` 字段是一项灵活的智能功能，
允许用户设置某次给定扫描报告的完成日期，并将其向下传播
到所有导入的发现项中。此字段**并非**必填，但该
字段的默认值为导入日期（即请求被处理并成功返回响应的那一刻）。

以下是使用该字段的几种情形：

1. 报告**未**设置日期，且导入时**未**设置 `scan_date`
    - 发现项日期将采用 `scan_date` 的默认值
2. 报告**设置**了日期，且导入时**未**设置 `scan_date`
    - 发现项日期将采用报告所设置的日期
3. 报告**未**设置日期，且导入时**设置**了 `scan_date`
    - 发现项日期将采用用户为 `scan_date` 所设置的值
4. 报告**设置**了日期，且导入时也**设置**了 `scan_date`
    - 发现项日期将采用用户为 `scan_date` 所设置的值
