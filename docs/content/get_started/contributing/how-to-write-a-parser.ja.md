---
title: パーサーへの貢献
description: パーサーへの貢献方法
draft: false
weight: 1
audience: opensource
aliases:
- /ja/en/open_source/contributing/how-to-write-a-parser
---

すべてのコマンドは、クローンしたdjango-DefectDojoリポジトリのルートにいることを前提としています。

## 前提条件

- https://github.com/DefectDojo/django-DefectDojo をフォークし、ローカルにクローンしていること。
- `dev`をチェックアウトし、最新の変更に追随していること。
- `git checkout -b parser-name`のように、開発用の専用ブランチを作成することを推奨します。

uWSGIのホットリロード機能があるため、docker composeでのデプロイを使用するのが最も簡単です。
環境をdev環境として設定します。

`$ docker/setEnv.sh dev`

詳細については[DOCKER.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md)を参照してください。

### Dockerイメージ

ローカルでdockerイメージをビルドし、イメージへの書き込みを可能にするために、必要に応じてローカルユーザーの`uid`を渡します(データベースのマイグレーションファイルを扱う際に便利です)。ユーザーの`uid`が`1000`だとすると、次のようになります。

{{< highlight bash >}}
$ docker compose build --build-arg uid=1000
{{< /highlight >}}

## 変更が必要なファイルは?

| ファイル                                          | 用途
|-------                                        |--------
|`dojo/tools/<parser_dir>/__init__.py`          | クラス初期化用の空ファイル
|`dojo/tools/<parser_dir>/parser.py`            | 本体部分。ここに実際のパーサーを実装します。クラス名は、アンダースコアを除いたPythonモジュール名に`Parser`を付加したものである必要があります。**例:** Pythonモジュール名が`dependency_check`の場合、クラス名は`DependencyCheckParser`になります。
|`unittests/scans/<parser_dir>/{many_vulns,no_vuln,one_vuln}.json` | ユニットテスト用の意味のあるデータを含むサンプルファイル。最小限のセットです。
|`unittests/tools/test_<parser_name>_parser.py` | パーサーのユニットテスト。
|`dojo/settings/settings.dist.py`               | 最新のハッシュコードベースの重複排除アルゴリズムを使用したい場合
|`docs/content/supported_tools/<file/api>/<parser_file>.md` | ドキュメント。必要なファイル形式の種類と、その取得方法


## ファクトリコントラクト

パーサーはファクトリパターンによって動的にロードされます。パーサーが正しくロードされ、動作するためには、このコントラクトを実装する必要があります。

1. パーサーはモジュール`dojo.tools`のサブモジュール内に**必ず**配置してください。
   - 例: `dojo.tools.my_tool.parser`モジュール
2. パーサーはこのサブモジュール内のクラスで**なければなりません**。
   - 例: `dojo.tools.my_tool.parser.MyToolParser`
3. このクラスの名前は、アンダースコアを除いたPythonモジュール名に`Parser`を付加したもので**なければなりません**。
   - 例: `dojo.tools.my_tool.parser.MyToolParser`
4. このクラスは、空のコンストラクタを持つか、コンストラクタを持たないもので**なければなりません**。
5. このクラスは4つのメソッドを**必ず**実装してください。
   1. `def get_scan_types(self)` パーサーがサポートするすべての*scan_type*のリストを返す関数です。この識別子は内部で使用されます。パーサーは複数の*scan_type*をサポートできます。たとえば、パーサーの挙動を変更するために異なる識別子を使用するパーサーもあります(集約、フィルタなど)。
   2. `def get_label_for_scan_types(self, scan_type):` UIに表示するテキスト(短いラベル)を返す関数です。
   3. `def get_description_for_scan_types(self, scan_type):` UIに表示するテキスト(長い説明)を返す関数です。
   4. `def get_findings(self, file, test)` 検出事項のリストを返す関数です。
6. パーサーが(詳細モード用に)複数のscan_typeを持つ場合、`def set_mode(self, mode)`メソッドを**必ず**実装してください。
7. パーサーのインスタンスは、このscan_typeに対して行われるすべてのインポートで再利用されるため、クラスレベルでデータを保持しないでください。

例:

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

## APIパーサー

DefectDojoにはAPIパーサーが少数存在します。これらのコネクタを削除することはありませんが、APIコネクタの追加には課題があり、サポート面の理由から、現時点ではコミュニティから新しいAPIパーサー/コネクタを受け付けることができません。高品質なAPIコネクタを維持するには、ツールのライセンスが必要です。そのライセンスを取得するには、作者またはベンダーとのパートナーシップが必要です。この課題に対応し、APIコネクタをDefectDojoにもたらすための新しいプログラムを近くお知らせする予定です。

## テンプレートジェネレーター

必要なファイルを素早く生成するには、[template](https://github.com/DefectDojo/cookiecutter-scanner-parser)パーサーを使用します。開始するには、[cookiecutter](https://github.com/cookiecutter/cookiecutter)をインストールする必要があります。

{{< highlight bash >}}
$ pip install cookiecutter
{{< /highlight >}}

次に、django-DefectDojoのルートからスキャナーパーサーを生成します。

{{< highlight bash >}}
$ cookiecutter https://github.com/DefectDojo/cookiecutter-scanner-parser
{{< /highlight >}}

テンプレートの設定変数については[こちら](https://github.com/DefectDojo/cookiecutter-scanner-parser)を参照してください。

## 注意すべき点

一般的なケースとエッジケースの両方でパーサーを堅牢にするための考慮事項のリストです。

### URLを手動でパースしない

エンドポイントの処理には2つのモジュールを使用しています。
 - `hyperlink`
 - エンドポイント`Endpoint`を作成するためのURL処理を扱う特定のクラスを持つ`dojo.models`

既存のパーサーはすべて、URLをパースしてエンドポイントを作成するために同じコードを使用しています。
エンドポイントを作成する最良の方法は`Endpoint.from_uri()`を使用することです。
どうしてもURLをパースする必要がある場合は、`hyperlink`モジュールを使用してください。

良い例:

```python
    if "url" in item:
        endpoint = Endpoint.from_uri(item["url"])
        finding.unsaved_endpoints = [endpoint]
```

非常に悪い例:

```python
    u = urlparse(item["url"])
    endpoint = Endpoint(host=u.host)
    finding.unsaved_endpoints = [endpoint]
```

### 情報のパースには適切なライブラリを使用する
さまざまなファイル形式はライブラリを通じて処理されます。DefectDojoをスリムに保ち、攻撃対象領域を広げないために、使用するライブラリの数は最小限にとどめ、他のパーサーを参考にしてください。

#### lxmlよりdefusedXMLを優先する
xmlはデフォルトで安全でない形式であるため、さまざまなxml出力から解析される情報は安全な方法でパースする必要があります。評価の結果、defusedXMLはより安全と評価されるライブラリであるため、今後パーサーでxmlファイルをパースする際にはこのライブラリを使用することを決定しました。そのため、defusedxmlライブラリを使用したPRのみを受け付けます。

### すべての属性が必須というわけではない

パーサーには多数のフィールドが存在する場合がありますが、その多くはオプションである可能性があります。
データがない場合は、`NA`や`No data`のような値で埋めるのではなく、属性を設定しない方が良いです。

クラス`dojo.models.Finding`を確認してください。

### ソースレポートにデータが欠けている場合がある

アップロードされるファイルに常に存在するとは確信が持てないフィールドについては、`KeyError`エラー(例: フィールドが存在しない)を避けるためのチェックを必ず含めてください。これらは500エラーにつながり、見た目もよくありません。

良い例:

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

最後の例は、`key_of_the_list`は存在するが`null`である場合に対応するためのものです。


### CVSSベクトルのパース

データには`CVSS`ベクトルまたはスコアが含まれる場合があります。Defect DojoはRedHat Securityが提供する`cvss`モジュールを使用します。
ベクトルを検証し、そこから基本スコアと深刻度を抽出するためのヘルパーメソッドも用意されています。

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
スキャンレポートは通常独自の`severity`値を提供するため、すべての値を使用する必要はありません。
`cvss_score`についても同様の場合があります。Defect Dojoは`cvss3_score`や`cvss4_score`を上書きしません。
スコアが設定されていない場合、Defect Dojoは`cvss`ライブラリを使用してスコアを計算します。
レスポンスには、検出されたCVSSベクトルのメジャーバージョンも`cvss_data["major_version"]`として含まれます。


より手動での処理が必要な場合は、`CVSS`ベクトルを直接パースすることもできます。

使用例:

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

次のようなことはしないでください。

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

## 重複排除アルゴリズム

デフォルトでは、新しいパーサーは[About Deduplication](/triage_findings/finding_deduplication/about_deduplication/)に記載されている「legacy」重複排除アルゴリズムを使用します。

該当する場合は、事前定義された重複排除アルゴリズムを使用してください。ハッシュコード設定で`unique_id_from_tool`または`vuln_id_from_tool`フィールドを使用する場合、これらの値が検出事項に対して一意であり、以降のスキャンにわたって時間的に一定であることが重要です。そうでない場合でも、重複排除には使用せずに、検出事項モデルにこれらの値を設定すること自体は有用な場合があります。
これらの値はレポートから直接得られるものでなければならず、パーサーが内部で計算した値であってはなりません。

## ユニットテスト

各パーサーは、少なくとも脆弱性0件、1件、複数件のケースをテストするユニットテストを持つ必要があります。まずは他のパーサーがどのようにテストを実装しているか見てみるとよいでしょう。質の高いテストが多いほど良いです。

検出事項の属性に対するチェックを追加することが重要です。
例:

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

### withを使用してサンプルファイルを開く

ファイルハンドルが確実に正しく閉じられるようにするため、ファイルを開く際はwithパターンを使用してください。
次のようにするのではなく、
```python
    testfile = open("path_to_file.json")
    ...
    testfile.close()
```

次のようにします。
```python
    with open("path_to_file.json") as testfile:
        ...
```

これにより、ブロック内のどこかで例外が発生した場合でも、with文の終了時にファイルが確実に閉じられます。

### テストデータベース

Djangoは、ユニットテストの実行に`test_defectdojo`という別のテストデータベースを使用します。これは自動的に作成され、基本的なテストデータのセットで初期化されます。

### テストの実行

このローカルコマンドは、新しいパーサーのユニットテストを起動します。

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.<your_unittest_py_file>.<main_class_name> -v2'
{{< /highlight >}}

または次のようにします。

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.<your_unittest_py_file>.<main_class_name>
{{< /highlight >}}

aquaパーサーの例:

{{< highlight bash >}}
$ docker compose exec uwsgi bash -c 'python manage.py test unittests.tools.test_aqua_parser.TestAquaParser -v2'
{{< /highlight >}}

または次のようにします。

{{< highlight bash >}}
$ ./run-unittest.sh --test-case unittests.tools.test_aqua_parser.TestAquaParser
{{< /highlight >}}

すべてのパーサーのユニットテストを実行したい場合は、`$ docker-compose exec uwsgi bash -c 'python manage.py test -p "test_*_parser.py" -v2'`を実行するだけです。

### エンドポイントの検証

パーサーの種類によっては、脆弱なエンドポイントのリストを作成するものがあります(これらは`finding.unsaved_endpoints`に格納されます)。DefectDojoでは、エンドポイントを特定の形式(RFCに準拠した形式)で保存する必要があります。この形式に従わないエンドポイントも保存できますが、破損しているものとしてマークされます(UI上の赤い旗🚩)。パーサーが正しい形式でエンドポイントを保存していることを確認するには、ユニットテスト内ですべてのエンドポイントに対して`.clean()`関数を実行してください。

```python
findings = parser.get_findings(testfile, Test())
for finding in findings:
    for endpoint in finding.unsaved_endpoints:
        endpoint.clean()
```

### APIパーサーのテスト

パーサーだけでなく、インポーターもテストする必要があります。
`unittest.mock`の`patch`メソッドは、APIレスポンスをシミュレートするのに通常役立ちます。
これを使用することを強く推奨します。

## その他の関連ファイル

### モデルの変更

より長い文字列データを保存できるようにデータベースのカラムサイズを増やすなど、モデルを変更する必要がある場合は、
* `dojo/models.py`内の必要な箇所を変更します。
* 以下を実行して、dojo/db_migrations内に新しいマイグレーションファイルを作成し、PRに含めます。

    {{< highlight bash >}}
    $ docker compose exec uwsgi bash -c 'python manage.py makemigrations -v2'
    {{< /highlight >}}

### アップロードを受け付ける別のファイル形式への対応

パーサーで新しいファイル形式を受け付けられるようにしたい場合は、`dojo/forms.py`の(本稿執筆時点で)436行目付近を確認するか、文字列`attrs={"accept":`が見つかる2箇所(importとre-import用)を探してください。

現在受け付けている形式: .xml、.csv、.nessus、.json、.html、.js、.zip。

### parser.py以外にもファイルが必要な場合

もちろん、`parser.py`ファイル以外にもファイルを持つことは何ら問題ありません。Pythonですから :-)

## プルリクエストの例

DefectDojoに現在組み込まれている過去のパーサーを確認したい場合は、https://github.com/DefectDojo/django-DefectDojo/pulls?q=is%3Apr+sort%3Aupdated-desc+label%3A%22Import+Scans%22+is%3Aclosed を参照してください。

## インポートページのドキュメントを更新する

新しいパーサーの詳細を記載した.mdファイルを[`docs/content/en/connecting_your_tools/parsers`]に追加してください。以下の見出しを含めてください。

* Acceptable File Type(s) - 関連ツールからこの種類のファイルを生成する方法を記載してください。ツールによっては複数の方法があったり、特定のコマンドが必要な場合があります。
* 該当する場合はユニットテストのブロックの例。
* ドキュメントからユーザーがすぐに移動できるよう、関連するユニットテストフォルダへのリンク。
* スキャナー自体へのリンク - (例: GitHubまたはベンダーへのリンク)

完成したパーサードキュメントページの例を以下に示します: [https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md](https://github.com/DefectDojo/django-DefectDojo/blob/master/docs/content/supported_tools/file/acunetix.md)
