---
title: DefectDojo API v2
description: DefectDojoのAPIを使用すると、CI/CDパイプラインでのスキャンレポートのアップロードなど、タスクを自動化できます。
draft: false
weight: 2
aliases:
- /ja/en/api/api-v2-docs
---

DefectDojoのAPIは[Django Rest
Framework](http://www.django-rest-framework.org/)を使用して作成されています。各エンドポイントのドキュメントは、各DefectDojoインストール内の
[`/api/v2/oa3/swagger-ui`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/)で利用でき、ヘッダーのユーザードロップダウンメニューにあるAPI v2
Docsリンクを選択することでアクセスできます。

![image](images/api_v2_1.png)

このドキュメントは[drf-spectacular](https://drf-spectacular.readthedocs.io/)を使用して[`/api/v2/oa3/swagger-ui/`](https://demo.defectdojo.org/api/v2/oa3/swagger-ui/)で生成されており、
インタラクティブに操作できます。API v2 Docsの上部には、OpenAPI v3仕様を生成するリンクがあります。

ドキュメントを操作するには、有効なAuthorizationヘッダーの値
が必要です。`/api/key-v2`ビューにアクセスしてAPIキー(`Token <api_key>`)を生成し、表示されたヘッダーの値をコピーしてください。

![image](images/api_v2_2.png)

各セクションでは、APIを呼び出し、リクエスト
URL、レスポンスボディ、レスポンスコード、レスポンスヘッダーを確認できます。

![image](images/api_v2_3.png)

Defect DojoのWeb UIにログインしている場合、認証トークンを指定する必要はありません。

## Authentication

APIはAPIキーによるヘッダー認証を使用します。ヘッダーの形式は次のとおりです: :

    Authorization: Token <api.key>

例: :

    Authorization: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

### Alternative authentication method

ユーザーに対して[代替の認証方式](/admin/sso/)を使用している場合、認証の仕組みを回避されてしまう可能性があるため、DefectDojoのAPIトークンを無効化することを検討してください。 \
DefectDojo APIトークンの使用は、環境変数`DD_API_TOKENS_ENABLED`を`False`に設定することで無効化できます。
または、`api/v2/api-token-auth/`エンドポイントのみを`DD_API_TOKEN_AUTH_ENDPOINT_ENABLED`を`False`に設定することで無効化できます。

## Sample Code

以下は、`/users`エンドポイントに対する簡単なPythonの例と、その実行結果です: :

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

このコードは、DefectDojoに定義されているすべてのユーザーのリストを返します。
JSONオブジェクトの結果は次のようになります: :

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

次に、`/users`エンドポイントに対する別の例を示します。今回は
ユーザー名に`jay`を含むユーザーのみに結果を絞り込みます:

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

JSONオブジェクトの結果は次のとおりです: :

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

APIとの連携に関する追加の例やヒントについては、[Django Rest Framework
のドキュメント](https://www.django-rest-framework.org/)を参照してください。

## Manually calling the API

Postmanなどのツールを使用してAPIをテストできます。

スキャン結果をインポートする例:

-   メソッド: POST
-   URI: <http://localhost:8080/api/v2/import-scan/>
-   ヘッダー タブ:

    認証ヘッダーを追加します
    :   -   キー: Authorization
        -   値: Token c8572a5adf107a693aa6c72584da31f4d1f1dcff

-   ボディ タブ

    -   \"form-data\"を選択し、\"bulk edit\"をクリックします。ZAPスキャンの例:

<!-- -->

    engagement:3
    verified:true
    active:true
    lead:1
    tags:test
    scan_type:ZAP Scan
    minimum_severity:Info
    close_old_findings:false

-   ボディ タブ

       -   \"Key-value\"編集をクリックします
       -   タイプが\"file\"の\"file\"パラメーターを追加します。これにより、ファイル
            内容を送信するためのマルチパートフォームデータがトリガーされます
       -   アップロードするファイルを参照します

-   送信をクリックします

## Clients / API Wrappers

| Wrapper                      | Status                   | Notes |
| -----------------------------| ------------------------| ------------------------|
| [Specific python wrapper](https://github.com/DefectDojo/defectdojo_api)      | 動作確認済み (2021-01-21)    | 継続的なCI/CDアップロード用のスクリプトを含むAPIラッパーです。APIラッパーの刷新を計画しているため、最新のAPI機能に対して多少遅れています。 |
| [Openapi python wrapper](https://github.com/alles-klar/defectdojo-api-v2-client)       | | OpenAPI仕様がまだ完全ではないことが判明した、概念実証のみの段階です。 |
| [Java library](https://github.com/secureCodeBox/defectdojo-client-java)                 | 動作確認済み (2021-08-30)    | [SecureCodeBox](https://github.com/secureCodeBox/secureCodeBox)の親切な方々によって作成されました。 |
| [Image using the Java library](https://github.com/SDA-SE/defectdojo-client) | 動作確認済み (2021-08-30)    | |
| [.Net/C# library](https://www.nuget.org/packages/DefectDojo.Api/)              | 動作確認済み (2021-06-08)    | |
| [dd-import](https://github.com/MaibornWolff/dd-import)                    | 動作確認済み (2021-08-24)    | dd-importは厳密にはAPIラッパーではありません。CI/CDパイプラインから検出事項や言語データをインポートしやすくするための便利な機能を提供します。 |

一部のAPIラッパーには、CI/CD環境でのスキャンやインポートを容易にするための多くのロジックが含まれています。DefectDojoのAPIをよりスマートにすることで、APIラッパーやスクリプト側をよりシンプルにできるよう、簡素化を進めています。

## API Notes

### Import / Reimport

**再インポート**は、必要に応じてその場でエンティティを作成し、初回アップロードか再アップロードかを自動的に検出するため、実際には最も簡単に始められる方法です。

## Import
APIを介したインポートは、[import-scan](https://demo.defectdojo.org/api/v2/doc/)エンドポイントを介して実行されます。

[製品階層](/asset_modelling/os_hierarchy/product_hierarchy/)で説明されているとおり、テストはエンゲージメント内に、エンゲージメントは製品内に、製品は製品タイプ内に作成されます。

これらのエンティティの名前をAPIリクエストで指定することで、インポートを実行できます:


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

`auto_create_context`が`True`の場合、必要に応じて製品、エンゲージメント、環境が作成されます。これを行うには、ユーザーが十分な[権限](/admin/user_management/about_perms_and_roles/)を持っている必要があります。

従来の方法として、エンゲージメントのIDを指定してスキャンをインポートすることもできます:

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
APIを介した再インポートは、[reimport-scan](https://demo.defectdojo.org/api/v2/doc/)エンドポイントを介して実行されます。

これらのエンティティの名前をAPIリクエストで指定することで、再インポートを実行できます:


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

`auto_create_context`が`True`の場合、製品タイプ、製品、エンゲージメントがまだ存在しなければ作成されます。製品/製品タイプを作成するには、ユーザーが十分な[権限](/admin/user_management/about_perms_and_roles/)を持っている必要があります。

`do_not_reactivate`が`True`の場合、インポート/再インポートの際にアップロードされたアクティブな検出事項は無視され、以前にクローズされた検出事項は再アクティブ化されません。ただし、新しい検出事項があればそれは引き続き作成されます。この理由により再アクティブ化されなかったことを説明するメモが、該当の検出事項に付与されます。

再インポートでは、指定されたエンゲージメント内で、指定された`scan_type`(および任意で指定された`test_title`)を満たす最新のテストが自動的に選択されます。

既存のテストが見つからない場合、再インポートエンドポイントはインポート機能を使用して、指定されたレポートを新しいテストにインポートします。これにより、APIを使用する(CI/CD)スクリプトは、この製品/エンゲージメントに対してテストが既に存在するかどうか、あるいは初回のアップロードであるかどうかを把握する必要がなくなります。

従来の方法として、テストのIDを指定してスキャンを再インポートすることもできます:

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

DefectDojoは、API経由で**JSON**、**HTML**、**CSV**、または**Excel**形式の検出事項レポートを生成できます。

レポートは、`generate_report/`アクションへの`POST`リクエストによって生成されます。findingsエンドポイントはインスタンス全体のレポートを扱い、その他のほとんどのオブジェクトはオブジェクトごとのアクションを公開しています:

| Endpoint | Scope |
|---|---|
| `POST /api/v2/findings/generate_report/` | 閲覧権限のあるすべての検出事項 |
| `POST /api/v2/products/{id}/generate_report/` | 1つの製品 |
| `POST /api/v2/engagements/{id}/generate_report/` | 1つのエンゲージメント |
| `POST /api/v2/tests/{id}/generate_report/` | 1つのテスト |
| `POST /api/v2/product_types/{id}/generate_report/` | 1つの製品タイプ |
| `POST /api/v2/endpoints/{id}/generate_report/` | 1つのエンドポイント |

Proオブジェクトのエイリアスも同じアクションを公開しています: `/api/v2/assets/{id}/generate_report/`、`/api/v2/organizations/{id}/generate_report/`、および`/api/v2/location/{id}/generate_report/`。

### Request options

すべてのフィールドは任意です — 空のボディ(`{}`)をPOSTするとJSONレポートが返されます。

| Field | Type | Default | Description |
|---|---|---|---|
| `report_type` | string | `JSON` | `JSON`、`HTML`、`CSV`、`Excel`のいずれか。 |
| `include_finding_notes` | boolean | `false` | 各検出事項のメモを含めます。 |
| `include_finding_images` | boolean | `false` | 検出事項に添付された画像を含めます。 |
| `include_executive_summary` | boolean | `false` | エグゼクティブサマリーセクションを含めます。 |
| `include_table_of_contents` | boolean | `false` | 目次を含めます。 |

サポートされていない`report_type`(例: `PDF`)を指定すると、`report_type`フィールドのエラーとともに`400 Bad Request`が返されます。

### Example

閲覧可能なすべての検出事項のCSVレポートを生成し、ファイルに保存します:

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
| `JSON` (default) | `application/json` | レスポンス内のレポート本文 |
| `HTML` | `text/html` | レンダリングされたレポートページ |
| `CSV` | `text/csv` | ファイル添付 |
| `Excel` | `application/vnd.openxmlformats-officedocument.spreadsheetml.sheet` | `.xlsx`ファイル添付 |

CSVとExcelは、JSON本文としてではなく、`Content-Disposition`ヘッダーを持つファイル添付として返されます。ファイル名は、レポートの生成元となったオブジェクトから決定されます — 例えば`product_1_findings.csv`や`test_42_findings.xlsx`のようになります。`/findings/generate_report/`エンドポイントは単一のオブジェクトに限定されないため、そのダウンロードファイルは`findings.csv`および`findings.xlsx`という名前になります。

### Notes and limitations

* `include_*`オプションは**JSON**および**HTML**レポートにのみ影響します。**CSV**および**Excel**のエクスポートには常にすべての検出事項の行が含まれます。
* レポートの生成には、対象オブジェクトに対する**閲覧**権限が必要であり、レポートにはユーザーが閲覧を許可されている検出事項のみが含まれます。
* **標準のクエリパラメータフィルターはこのアクションには適用されません。** `GET /api/v2/findings/`とは異なり、`generate_report/`アクションは検出事項のフィルターを適用しないため、`POST /api/v2/findings/generate_report/?severity=High`のようなリクエストを送信しても、閲覧可能なすべての検出事項がレポートされます。レポートを絞り込むには、代わりに特定の製品、エンゲージメント、またはテストから生成してください。

## Asynchronous Deletion Behavior

DefectDojoでの削除操作(APIとUIの両方経由)は、Celeryのバックグラウンドワーカーによって**非同期的に**処理されます。エンゲージメント、テスト、その他のオブジェクトを削除すると、APIまたはUIは即座に成功レスポンスを返しますが、実際の削除処理はバックグラウンドで実行されます。

つまり:
- 削除が確認された後もしばらくの間、オブジェクトがクエリ結果に表示され続けることがあります。
- カスケード削除(例: エンゲージメントを削除すると、そのテストと検出事項も削除される)は、一連のバックグラウンドタスクとして処理されます。子オブジェクトは依存関係の順序で削除されます: 検出事項、次にテスト、次にエンゲージメントの順です。
- 検出事項が多い大規模なエンゲージメントの場合、この処理が完了するまでに数分かかることがあります。

オブジェクトを依存関係の順序で削除するためのカスタムスクリプトを作成する必要はありません。エンゲージメントに対して単一の`DELETE`リクエストを送信するだけで、すべての子オブジェクトが自動的にカスケード削除されます。バックグラウンドタスクが完了するまで、時間を置いて待つだけで構いません。

## API Pagination Limits

DefectDojo Proでは、APIリクエストあたりの最大ページサイズが**250**件に制限されています。`limit`を250より大きく設定すると、クエリタイムアウトによりHTTP 502エラーが発生する可能性があります。

オープンソース版のDefectDojoインスタンスでも、データセットのサイズやサーバーリソースによっては、非常に大きなページサイズでタイムアウトが発生する場合があります。

大量の結果セットを扱う場合は、50〜250件のページサイズでページネーションを使用し、ページ分割されたリクエストの間に短い遅延を挟んでワーカープールの過負荷を避けてください。

## Large-Scale Import Best Practices

大量のスキャン結果をインポートする場合(例: 数千のコンポーネントを含むSBOMパイプライン)、以下の点を考慮してください:

- **大きなペイロードには`background_import=true`を使用してください。** 同期インポートは、インポートが完了するまでuwsgiワーカーを占有するため、すべてのユーザーのパフォーマンスが低下する可能性があります。
- **可能な限り、インポートあたりのペイロードサイズを1MB未満に抑えてください。** 大きなSBOMは、製品またはコンポーネントグループごとに小さなファイルに分割してください。
- **連続するAPI呼び出しの間に遅延を追加してください。** そうしないと、ワーカープールが枯渇し、HTTP 502エラーが発生します。
- **繰り返し行うスキャンには再インポート**(`/api/v2/reimport-scan/`)を使用し、重複を作成するのではなく既存の検出事項を更新してください。

## Background import responses (API: `background_import`)

バックグラウンドインポートは、アップロードされたレポートが解析され次第、検出事項が書き込まれる前にレスポンスを返します。そのため、レスポンスは*スケジュールされた*処理内容を表しており、同期インポートとは異なる形をしています。これは、`background_import`が`true`の場合、または`api_async_import`システム設定によってすべてのインポートで有効化されている場合の、`/api/v2/import-scan/`および`/api/v2/reimport-scan/`に適用されます。

バックグラウンドレスポンスには次の内容が含まれます:

- `background_import` — `true`。この値によって処理を分岐させます。
- `status` — レスポンスが生成された時点でのテストのライフサイクルステータス:
  `Processing`、`Post Processing - Deduplication`、
  `Post Processing - False Positive History`、`Processed`、`Failed`のいずれか。
- `findings_parsed` — レポートから読み取られた検出事項の数。これは解析件
  数であり、作成件数ではありません。重複排除や指定したインポートオプションによって、
  実際に書き込まれる検出事項の数が決まります。
- `test_id`(および`engagement_id`、`product_id`、`product_type_id`) — ポーリングに使用する
  識別子。
- `message` — `status`と`findings_parsed`と同じ情報を文章で表したものです。
  構造化されたフィールドの使用を推奨します。

バックグラウンドインポートには`statistics`は**含まれず**、`deduplication_complete`も含まれません。
これらのキーは、その時点でまだ検出事項が作成されておらず、ゼロを報告するとインポートの状態を誤って伝えることになるため、値が
ゼロなのではなく存在しないのです。`response["statistics"]`を無条件に読み取るクライアントは、バックグラウンドインポートで失敗します。先に
`background_import`を確認するか、`statistics`は同期処理のパスでのみ使用してください。

バックグラウンドインポートを完了まで追跡するには、テストをポーリングします:

```
POST /api/v2/import-scan/        (background_import=true)  -> test_id, status, findings_parsed
GET  /api/v2/tests/{test_id}/                              -> status, processing
```

`status`が`Processed`(インポートが完了し、テストの検出事項数が意味を持つ状態になった)または`Failed`(インポートが完了しなかった)に
なるまで、`GET`を繰り返してください。インポートの実行中は、`processing`が`true`になり、`status`は現在のフェーズを示します。
ポーリングの間隔は数秒空けてください。大きなレポートでは、後処理に数分かかることがあります。

同期インポート(`background_import`を省略、または`false`)の動作は変わりません。検出事項の書き込みが完了した時点でレスポンスが返され、`statistics`
が含まれ、`status`や`findings_parsed`は含まれません。

## Using the Scan Completion Date (API: `scan_date`) field

DefectDojoは非常に多くのスキャナーレポート形式をサポートしていますが、そのすべてがユーザーにとって最も重要な
情報を含んでいるわけではありません。`scan_date`フィールドは、指定されたスキャンレポートの完了日を設定し、それをインポートされたすべての検出事項に伝播させることが
できる柔軟なスマート機能です。このフィールドは**必須ではありません**が、指定しない場合のデフォルト値はインポート日(リクエストが処理され、成功レスポンスが返された時点の日付)になります。

このフィールドの使用例は次のとおりです:

1. レポートに日付が設定されて**おらず**、インポート時に`scan_date`も設定され**ていない**場合
    - 検出事項の日付は`scan_date`のデフォルト値になります
2. レポートに日付が**設定されており**、インポート時に`scan_date`が設定され**ていない**場合
    - 検出事項の日付はレポートが設定した値になります
3. レポートに日付が設定されて**おらず**、インポート時に`scan_date`が**設定されている**場合
    - 検出事項の日付はユーザーが`scan_date`に設定した値になります
4. レポートに日付が**設定されており**、インポート時に`scan_date`も**設定されている**場合
    - 検出事項の日付はユーザーが`scan_date`に設定した値になります
