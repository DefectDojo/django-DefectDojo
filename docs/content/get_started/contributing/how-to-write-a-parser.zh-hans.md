---
title: 贡献解析器
description: 如何为解析器做贡献
draft: false
weight: 1
audience: opensource
aliases:
- /zh-hans/en/open_source/contributing/how-to-write-a-parser
---

所有命令均假设您位于 django-DefectDojo 克隆仓库的根目录下。

## 前提条件

- 您已经 fork 了 https://github.com/DefectDojo/django-DefectDojo 并克隆到本地。
- 检出（checkout）`dev` 分支，并确保已同步到最新更改。
- 建议您为开发创建一个专用分支，例如 `git checkout -b parser-name`。

使用 docker compose 部署方式最为简便，因为它具备 uWSGI 的热重载能力。
将您的环境设置为使用 dev 环境：

`$ docker/setEnv.sh dev`

更多详情请参阅 [DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md)。

### Docker 镜像

您需要在本地构建 docker 镜像，并最终传入本地用户的 `uid`，以便能够写入镜像内容（这对数据库迁移文件很有用）。假设您用户的 `uid` 为 `1000`，则：

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## 您需要修改哪些文件？

| 文件                                          | 用途
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | 用于类初始化的空文件
|`dojo/tools/<parser_dir>/parser.py`            | 核心内容。您在此处编写实际的解析器。类名必须是不含下划线的 Python 模块名加上 `Parser`。**示例：**当 Python 模块名为 `dependency_check` 时，类名应为 `DependencyCheckParser`
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | 包含有意义数据的示例文件，用于单元测试。这是最小集合。
|`unittests/tools/test_<parser_name>_parser.py` | 该解析器的单元测试。
|`dojo/settings/settings.dist.py`               | 如果您想使用基于现代哈希码的去重算法
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | 文档，说明所需的文件格式类型以及如何获取该文件


## 工厂契约

解析器通过工厂模式动态加载。要使您的解析器被正确加载并正常工作，您需要实现该契约。

1. 您的解析器**必须**位于模块 `dojo.tools` 的子模块中
   - 例如：`dojo.tools.my_tool.parser` 模块
2. 您的解析器**必须**是该子模块中的一个类。
   - 例如：`dojo.tools.my_tool.parser.MyToolParser`
3. 该类的名称**必须**是不含下划线的 Python 模块名，并加上 `Parser` 后缀。
   - 例如：`dojo.tools.my_tool.parser.MyToolParser`
4. 该类**必须**具有空构造函数，或不含构造函数
5. 该类**必须**实现 4 个方法：
   1. `def get_scan_types(self)` 该函数返回您的解析器支持的所有 *scan_type* 的列表。这些标识符在内部使用。您的解析器可以支持多个 *scan_type*。例如，某些解析器使用不同的标识符来修改解析器的行为（聚合、过滤等）
   2. `def get_label_for_scan_types(self, scan_type):` 该函数返回一个字符串，用于在 UI 中提供部分文本（短标签）
   3. `def get_description_for_scan_types(self, scan_type):` 该函数返回一个字符串，用于在 UI 中提供部分文本（长描述）
   4. `def get_findings(self, file, test)` 该函数返回发现项（findings）列表
6. 如果您的解析器有多个 scan_type（用于详细模式），您**必须**实现 `def set_mode(self, mode)` 方法
7. 解析器实例会在针对该 scan_type 执行的所有导入操作中被重复使用，因此请勿在类级别存储任何数据

示例：

```Python

class MyToolParser(object):
    def get_scan_types(self):
        return ["My Tool Scan", "My Tool Scan detailed"]

    def get_label_for_scan_types(self, scan_type):
        if scan_type == "My Tool Scan":
            return "My Tool XML Scan aggregated by ..."
        else:
            return "My Tool XML Scan"

    def get_description_for_scan_types(self, scan_type):
        return "Aggregates findings per cwe, title, description, file_path. SonarQube output file can be imported in HTML format. Generate with https://github.com/soprasteria/sonar-report version >= 1.1.0"

    def requires_file(self, scan_type):
        return False

    # mode:
    # None (default): aggregates vulnerabilites per sink filename (legacy behavior)
    # 'detailed' : No aggregation
    mode = None

    def set_mode(self, mode):
        self.mode = mode

    def get_findings(self, file, test):
        <...>

```

## API 解析器

DefectDojo 目前拥有数量有限的 API 解析器。虽然我们不会移除这些连接器，但添加 API 连接器一直存在问题，出于可支持性方面的考虑，我们目前无法接受社区提交的新 API 解析器/连接器。要维持高质量的 API 连接器，必须拥有该工具的许可证，而获得许可证需要与作者或供应商建立合作关系。我们即将宣布一项新计划，以帮助解决这一问题，并将 API 连接器引入 DefectDojo。

## 模板生成器

使用[模板](https://github.com/DefectDojo/cookiecutter-scanner-parser)解析器可以快速生成所需的文件。开始之前，您需要安装 [cookiecutter](https://github.com/cookiecutter/cookiecutter)。

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

然后从 django-DefectDojo 的根目录生成您的扫描器解析器：

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

阅读[更多信息](https://github.com/DefectDojo/cookiecutter-scanner-parser)，了解模板配置变量。

## 需要注意的事项

以下是一些注意事项，可使解析器在常见情况和边缘情况下都更加健壮。

### 不要手动解析 URL

我们使用 2 个模块来处理端点：
 - `hyperlink`
 - `dojo.models`，其中有一个专门的类用于处理围绕 URL 创建端点 `Endpoint` 的相关逻辑。

所有现有解析器都使用相同的代码来解析 URL 并创建端点。
使用 `Endpoint.from_uri()` 是创建端点的最佳方式。
如果您确实需要解析 URL，请使用 `hyperlink` 模块。

良好示例：

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

非常糟糕的示例：

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### 使用合适的库来解析信息
各种文件格式都是通过库来处理的。为了保持 DefectDojo 的精简，同时不扩大攻击面，请将所使用的库数量保持在最少，并以其他解析器为参考。

#### 使用 defusedXML 而非 lxml
由于 xml 默认是一种不安全的格式，从各种 xml 输出中解析出的信息必须以安全的方式进行解析。经过评估，我们确定今后在解析器中解析 xml 文件时将使用 defusedXML 库，因为该库被评定为更安全。因此，我们只会接受使用 defusedxml 库的 PR。

### 并非所有属性都是必填的

解析器可能包含许多字段，其中许多可能是可选的。
如果没有相应的数据，最好不设置该属性，而不是填入 `NA`、`No data` 等值……

请查看 `dojo.models.Finding` 类

### 源报告中可能缺少数据

对于那些您不能完全确定一定会出现在上传文件中的字段，请务必加入检查，以避免潜在的 `KeyError` 错误（例如字段不存在）。这类错误会转化为 500 错误，观感不佳。

良好示例：

```python
   if "mykey" in data:
       finding.cwe = data["mykey"]
```

```python
   finding.cwe = data.get("mykey", 123)
```

```python
   some_list = data.get("key_of_the_list") or []
```

最后一个示例可以防范 `key_of_the_list` 存在但值为 `null` 的情况。


### 解析 CVSS 向量

数据中可能包含 `CVSS` 向量或分数。Defect Dojo 使用 RedHat Security 提供的 `cvss` 模块。
还有一个辅助方法，可用于验证该向量并从中提取基础分数和严重程度。

```python
    from dojo.utils import parse_cvss_data

    cvss_vector = <get CVSS3 or CVSS4 vector from the report>
    cvss_data = parse_cvss_data(cvss_vector)
    if cvss_data:
        finding.severity = cvss_data["severity"]
        finding.cvssv3 = cvss_data["cvssv3"]
        finding.cvssv4 = cvss_data["cvssv4"]
        # we don't set any score fields as those will be overwritten by Defect Dojo
```
并非所有值都必须使用，因为扫描报告通常会提供自己的 `severity` 值。
有时也会提供 `cvss_score`。Defect Dojo 不会覆盖任何 `cvss3_score` 或 `cvss4_score`。
如果未设置分数，Defect Dojo 将使用 `cvss` 库来计算分数。
响应中还包含检测到的 CVSS 向量主版本号，位于 `cvss_data["major_version"]` 中。


如果您需要更多手动处理，可以直接解析 `CVSS` 向量。

使用示例：

```python
    import cvss.parser
    from cvss import CVSS2, CVSS3, CVSS4

    # TEMPORARY: Use Defect Dojo implementation of `parse_cvss_from_text` white waiting for https://github.com/RedHatProductSecurity/cvss/pull/75 to be released
    vectors = cvss.parser.parse_cvss_from_text("CVSS:3.0/S:C/C:H/I:H/A:N/AV:P/AC:H/PR:H/UI:R/E:H/RL:O/RC:R/CR:H/IR:X/AR:X/MAC:H/MPR:X/MUI:X/MC:L/MA:X")
        if len(vectors) > 0 and type(vectors[0]) is CVSS3:
            print(vectors[0].severities())  # this is the 3 severities

            cvssv3 = vectors[0].clean_vector()
            severity = vectors[0].severities()[0]
            vectors[0].compute_base_score()
            cvssv3_score = vectors[0].scores()[0]
            finding.severity = severity
            finding.cvssv3_score = cvssv3_score
```

请勿采用以下这种做法：

```
    def get_severity(self, cvss, cvss_version="2.0"):
        cvss = float(cvss)
        cvss_version = float(cvss_version[:1])
        # If CVSS Version 3 and above
        if cvss_version >= 3:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss < 9:
                return "High"
            elif cvss >= 9:
                return "Critical"
            else:
                return "Informational"
        # If CVSS Version prior to 3
        else:
            if cvss > 0 and cvss < 4:
                return "Low"
            elif cvss >= 4 and cvss < 7:
                return "Medium"
            elif cvss >= 7 and cvss <= 10:
                return "High"
            else:
                return "Informational"
```

## 去重算法

默认情况下，新的解析器使用"旧版（legacy）"去重算法，该算法记录在[关于去重](/triage_findings/finding_deduplication/about_deduplication/)中

请在适用的情况下使用预定义的去重算法。在哈希码配置中使用 `unique_id_from_tool` 或 `vuln_id_from_tool` 字段时，重要的是这些值对于该发现项必须是唯一的，并且在后续扫描中长期保持不变。如果无法满足这一点，这些值仍然可以在发现项模型中设置，只是不用于去重。
这些值必须直接来自报告本身，而不能是解析器内部计算得出的值。

## 单元测试

每个解析器都必须有单元测试，至少要测试 0 个漏洞、1 个漏洞和多个漏洞的情况。您可以先参考其他解析器的做法。高质量的测试越多越好。

为发现项的各项属性添加检查非常重要。
例如：

```python
        with self.subTest(i=0):
            finding = findings[0]
            self.assertEqual("test title", finding.title)
            self.assertEqual(True, finding.active)
            self.assertEqual(True, finding.verified)
            self.assertEqual(False, finding.duplicate)
            self.assertIn(finding.severity, Finding.SEVERITIES)
            self.assertEqual("CVE-2020-36234", finding.vulnerability_ids[0])
            self.assertEqual(261, finding.cwe)
            self.assertEqual("CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N", finding.cvssv3)
            self.assertIn("security", finding.tags)
            self.assertIn("network", finding.tags)
            self.assertEqual("3287f2d0-554f-491b-8516-3c349ead8ee5", finding.unique_id_from_tool)
            self.assertEqual("TEST1", finding.vuln_id_from_tool)
```

### 使用 with 打开示例文件

为确保文件句柄能够被正确关闭，请使用 with 语句模式来打开文件。
不要这样写：
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

而应这样写：
```python
    with open("path_to_file.json") as testfile:
        ...
```

这样可以确保文件在 with 语句结束时被关闭，即使代码块中某处发生异常也是如此。

### 测试数据库

Django 使用一个名为 `test_defectdojo` 的独立测试数据库来运行单元测试。该数据库会自动创建，并初始化一组基本的测试数据。

### 运行您的测试

以下本地命令将启动您新解析器的单元测试

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

或者像这样：

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

以 aqua 解析器为例：

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

或者像这样：

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

如果您想运行所有解析器的单元测试，只需运行 `$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'`

### 端点验证

某些类型的解析器会创建一个存在漏洞的端点列表（存储在 `finding.unsaved_endpoints` 中）。DefectDojo 要求以特定格式（遵循 RFC）存储端点。不符合该格式的端点仍可被存储，但会在 UI 中被标记为异常（红旗 🚩）。为确保您的解析器以正确格式存储端点，请在单元测试中对所有端点运行 `.clean()` 函数

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### 测试 API 解析器

不仅要测试解析器，还应测试导入器（importer）。
`unittest.mock` 中的 `patch` 方法通常有助于模拟 API 响应。
强烈建议使用该方法。

## 可能涉及的其他文件

### 修改模型

如果您需要修改模型，例如增加数据库列的大小以容纳需要保存的更长字符串数据
* 在 `dojo/models.py` 中进行所需的修改
* 通过运行以下命令在 dojo/db_migrations 中创建一个新的迁移文件，并将其包含在您的 PR 中

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### 接受不同类型的上传文件

如果您希望解析器能够接受新的文件类型，请查看 `dojo/forms.py` 中大约第 436 行（截至本文写作时）的位置，或找到出现字符串 `attrs={"accept":` 的 2 处位置（分别用于导入和重新导入）。

目前接受的格式：.xml、.csv、.nessus、.json、.html、.js、.zip。

### 不仅仅需要 parser.py

当然，没有什么能阻止您拥有比 `parser.py` 更多的文件。毕竟这是 Python :-)

## Pull Request 示例

如果您想查看已经成为 DefectDojo 一部分的以往解析器，请访问 https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed

## 更新导入页面文档

请在 [`docs/content/en/connecting_your_tools/parsers`] 中添加一个新的 .md 文件，写明您新解析器的详细信息。请包含以下内容标题：

* 可接受的文件类型——请说明如何从相关工具生成此类文件，因为某些工具具有多种生成方法或需要特定命令。
* 一个示例单元测试代码块（如适用）。
* 一个指向相关单元测试文件夹的链接，以便用户可以从文档中快速导航到该处。
* 一个指向扫描器本身的链接（例如 GitHub 或供应商链接）

以下是一个已完成的解析器文档页面示例：[https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
