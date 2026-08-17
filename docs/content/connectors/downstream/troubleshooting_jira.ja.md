---
title: Jira エラーのトラブルシューティング (レガシー)
description: Jira 連携の問題を修正する
weight: 2
aliases:
- /ja/issue_tracking/jira/troubleshooting_jira/
- /ja/en/share_your_findings/troubleshooting_jira/
---

Jira 連携でよくある問題と、その対処方法を以下に示します。

## DefectDojo に Jira の設定が見当たらない

サイドバーに Jira メニューがなく、製品 / エンゲージメントのフォームに Jira セクションがなく、検出事項に **Push to Jira** オプションも表示されない場合、Jira 連携がシステム設定でまだ無効になっている可能性が高いです。DefectDojo は、有効化されるまですべての Jira コントロールを非表示にします。

システム設定ページで **Enable Jira Integration** を確認してください:

* オープンソース版: ⚙️ **Configuration \> System Settings** を開き、**Enable JIRA integration** をチェックします。フォームを保存するには **Jira webhook secret** も必要なので、🔄 アイコンをクリックして生成してください。詳細は [Jira 連携ガイド](/connectors/os_jira/os__jira_guide/#step-1-enable-the-jira-integration-in-system-settings) を参照してください。
* Pro 版: **\<Your Edition\> Settings \> System Settings** を開き、**Jira Integration Settings** の下にある **Enable Jira Integration** をチェックします。詳細は [Jira 連携ガイド](/connectors/downstream/pro__jira_guide/#step-1-enable-the-jira-integration-in-system-settings) を参照してください。

設定がすでに有効になっているのに Jira メニューが表示されない場合、ユーザーに **View Jira Instance** 設定権限が付与されていない可能性があります。この権限もメニューを表示するために必要です。この権限は、ユーザーページで直接、またはユーザーグループを通じて割り当てることができます。詳細は [権限とロールについて](/admin/user_management/about_perms_and_roles/#configuration-permissions) を参照してください。

## DefectDojo が Jira (またはその他の送信先サービス) にまったく接続できない

DefectDojo の Jira 連携が「connection refused」「no route to host」、または一般的な TLS ハンドシェイクエラーのような接続エラーで失敗し、かつ認証情報自体は有効である場合、DefectDojo インスタンスがファイアウォールの内側にあり、送信トラフィックがフォワード HTTPS プロキシを経由する必要があるのかもしれません。

オンプレミスの Pro 版デプロイメントでは、デプロイメント上に `HTTPS_PROXY` / `HTTP_PROXY` / `NO_PROXY` 環境変数を設定してください。`dojo-compose-cli` はこれらを `uwsgi`、`celeryworker`、Connector の各コンテナに自動的に伝播します。設定手順の全体については [フォワード HTTPS プロキシの背後で DefectDojo を実行する](/onprem_deployment/forward_proxy/) を参照してください。

> Note: `HTTPS_PROXY` の設定は、DefectDojo からの **送信 (outbound)** トラフィックのみを構成します。Jira から DefectDojo への **受信 (inbound)** Webhook の配信には影響しません。そのケースについては、以下の [Jira issue の変更が DefectDojo の検出事項に反映されない](#changes-made-to-jira-issues-are-not-updating-findings-in-defectdojo) を参照してください。

## 404、401、403 エラーにより DefectDojo で Jira 設定をセットアップできない
Jira Cloud:
- 認証については Jira Cloud REST API のドキュメントを参照してください: https://developer.atlassian.com/cloud/jira/software/basic-auth-for-rest-apis/
- 提供された認証情報が Jira 内の必要な issue にアクセスできることを、コマンドラインで確認してください:

```
curl -D- \
   -u <emailaddress>:<personal_access_token> \
   -X GET \
   -H "Content-Type: application/json" \
   https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

例:
```
curl -D- \
   -u defectdojo@example.com:ATATT1234567890abcdefghijklmnopqrstuvwxyz \
   -X GET \
   -H "Content-Type: application/json" \
   https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

Jira Data Center または Server:
- 認証については Jira Data Center REST API のドキュメントを参照してください:
    - https://developer.atlassian.com/server/jira/platform/basic-authentication/ (ユーザー名 + パスワード)
    - https://confluence.atlassian.com/enterprise/using-personal-access-tokens-1026032365.html (個人アクセストークン)
- 提供された認証情報が Jira 内の必要な issue にアクセスできることを、コマンドラインで確認してください:

```
curl -u username:password -X GET -H "Content-Type: application/json" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

例:
```
curl -u defectdojo@example.com:123456 -X GET -H "Content-Type: application/json" https://defectdojo.atlassian.net/rest/api/latest/issue/VULNERABILITY-1/transitions?expand=transitions.fields
```

個人アクセストークンを使用する場合:
```
curl -H "Authorization: Bearer <personal_access_token>" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

例:
```
curl -H "Authorization: Bearer ATATT1234567890abcdefghijklmnopqrstuvwxyz" https://<COMPANY>.atlassian.net/rest/api/latest/issue/<JIRA_ISSUE_KEY>/transitions?expand=transitions.fields
```

## Jira サービスアカウントはサポートされていません

Jira Cloud のサービスアカウント (Atlassian の管理コンソール経由で作成されるもの) は、標準のユーザーアカウントとは異なる API ホストを使用するため、DefectDojo の Jira 連携では **現在サポートされていません**。サービスアカウントの API トークンや OAuth 2.0 認証情報を使用しようとすると、HTTP 403 エラーが発生します。

Jira 連携をセットアップするには、標準の Jira ユーザーアカウント (有効なメールアドレスを持つもの) を作成し、そのアカウントから API トークンを生成してください。DefectDojo によって作成された issue を明確に識別したい場合は、「DefectDojo」のような名前の専用ユーザーを作成し、その API トークンを連携に使用してください。

## Space の Epic Name ID が見つからない
Team-Managed Space など、Jira の一部の Space では Epic を使用しないため、Epic Name ID も存在しません。この場合は、DefectDojo で Epic Name ID を 0 に設定してください。

## 'Push To Jira' した検出事項が Jira に表示されない
'Push To Jira' ワークフローを使用すると非同期処理がトリガーされますが、'Push To Jira' が実行されてからかなり早く Jira 上に issue が作成されるはずです。

* 処理が成功したかどうかは、DefectDojo の通知で確認してください。push が失敗した場合、通知に Jira からのエラーレスポンスが表示されます。

issue が作成されない一般的な原因:
* 選択した Default Issue Type がその Jira Space で使用できない
* その Space の issue に必須の属性があり、DefectDojo からの作成を妨げている (これは Jira の Custom Fields で対処できます)


## エラー: Product Misconfigured or no permissions in Jira?

このエラーメッセージは、作成した Jira 設定を製品に追加しようとしたときに表示されることがあります。DefectDojo は Jira への接続を検証しようとし、その接続が失敗すると、このエラーメッセージが発生します。

* 選択した Jira Space で issue を作成する権限が、Jira の認証情報に付与されているか確認してください。
* 「Project Key」フィールドには、有効な Jira Space を指定する必要があります。Jira の issue は 1 つの Space 内で多くの異なる Key を使用できます。Project Key を確認する最も簡単な方法は、その Jira Space の URL を見ることです。通常は `https://xyz.atlassian.net/jira/core/projects/JTV/board` のような形式になります。この場合、`JTV` が Space Key です。

## Jira issue の変更が DefectDojo の検出事項に反映されない

* まず、DefectDojo の webhook レシーバーが正しく設定されており、更新を正常に受信できることを確認してください。

* DefectDojo が使用する SSL 証明書が JIRA に信頼されていることを確認してください。JIRA Cloud では、[グローバルに信頼された認証局によって署名された有効な SSL/TLS 証明書](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/) を使用する必要があります。

* ステータスの変更を push しようとしている場合は、Jira の transition マッピング (Reopen / Close Transition ID) が正しく設定されていることを確認してください。

* Pipedream や Beeceptor のようなパブリックエンドポイントを使用して、JIRA webhook を [テスト](https://support.atlassian.com/jira/kb/testing-webhooks-in-jira-cloud/) してください:

* 検出事項が実際に Jira issue にリンクされていることを確認してください。issue が DefectDojo の検出事項にリンクされていない場合でも webhook リクエストは受け付けられます (HTTP `200`) が、検出事項は更新されません。

* このエンドポイントは、更新が適用されたかどうかにかかわらず、**常に HTTP `200` を返す** ことに注意してください。送信側 (システム webhook や Jira Automation ルール) で `200` が返っても、その変更が検出事項に反映されたことを意味しません。実際の結果を確認するには、レスポンスボディと DefectDojo のログを確認してください。

* システム webhook の代わりに **Jira Automation** (*Send web request*) を使用している場合は、以下を確認してください:
    * リクエストの **Body** が **Custom data** に設定されており、トップレベルの `webhookEvent` として `"jira:issue_updated"` または `"comment_created"` のいずれかを含んでいること。**Empty** と **Jira issue data** の body オプションではこのフィールドが省略されるため、DefectDojo は認識できない `webhookEvent` を持つリクエストをすべて無視します。
    * リクエストに `Content-Type: application/json` が設定されていること — DefectDojo はそれ以外の content type を拒否します。
    * issue の更新では、`issue.id` は issue key ではなく **数値** の Jira issue ID (`{{issue.id}}`) であること、また `resolution` と `updated` の両方のフィールドが存在すること (`resolution` は `null` でも構いません)。`resolution` / `updated` が欠けていると、リクエストは何も表示されずにスキップされます。
    * コメントの場合、`comment.self` の URL の `.../issue/<id>/comment/...` セグメントに数値の `{{issue.id}}` が含まれていること、また `body` と `updateAuthor` の両方が存在すること。
    * コメントが表示されない場合は、**ループ防止** の仕組みを確認してください。コメントの投稿者が DefectDojo がコメント投稿に使用している Jira アカウントと一致する場合、DefectDojo はそのコメントをスキップします。そうしたコメントも取り込みたい場合は、Automation ルールを別の Jira ユーザーとして実行してください。
    * Automation のペイロードプレビューを使用して、smart value が期待どおりに解決されることを確認してください。名前は Jira インスタンスによって異なる場合があります。

## Jira の Epic が作成されない

`"Field 'customfield_xyz' cannot be set. It is not on the appropriate screen, or unknown."`

DefectDojo の Jira 連携には 'Epic Name' の customfield 値が必要です。しかし、プロジェクトの設定では、Epic を作成する際に 'Epic Name' がフィールドとして実際には使用されていない場合があります。Atlassian は [2023 年 8 月](https://community.atlassian.com/t5/Jira-articles/Upcoming-changes-to-epic-fields-in-company-managed-projects/ba-p/1997562) に、'Epic Name' と 'Epic Summary' の各フィールドを統合する変更を行いました。

新しい Jira Space では、デフォルトで Epic 作成時にこのフィールドを使用しない場合があり、その結果このエラーメッセージが発生します。

この問題を解決するには、プロジェクトの issue 作成画面に 'Epic Name' フィールドを追加します:

1. Jira UI から手動で Epic の作成を試みます。
2. 「...」メニューを開きます。
3. 'Find Your Field' をクリックします。
4. 'Epic Name' と入力します。
5. Jira の案内に従って、この画面に Epic Name をフィールドとして追加します。

![image](images/epic_name_error.png)

## JIRA 接続のリトライとタイムアウトの設定

DefectDojo の JIRA 連携には、レート制限や接続の問題に対処するための、設定可能なリトライおよびタイムアウトの設定が含まれています。これらの設定は、特に Celery worker を使用している場合に、システムの応答性を維持するうえで重要です。

### 利用可能な設定変数

以下の環境変数が JIRA 接続の挙動を制御します:

- **`DD_JIRA_MAX_RETRIES`** (デフォルト: `3`): 回復可能なエラーに対するリトライ試行の最大回数。この連携は、HTTP 429 (Too Many Requests)、HTTP 503 (Service Unavailable)、および接続エラーの場合に自動的にリトライします。詳細は [JIRA のレート制限ドキュメント](https://developer.atlassian.com/cloud/jira/platform/rate-limiting/) を参照してください。

- **`DD_JIRA_CONNECT_TIMEOUT`** (デフォルト: `10` 秒): JIRA サーバーへの接続を確立するための接続タイムアウト。

- **`DD_JIRA_READ_TIMEOUT`** (デフォルト: `30` 秒): 接続確立後に JIRA サーバーからのレスポンスを待機する読み取りタイムアウト。

**レート制限に関する注意**: jira ライブラリには、レート制限のリトライに対する組み込みの最大待機時間として 60 秒が設定されています。JIRA の `Retry-After` ヘッダーが 60 秒を超える待機時間を示している場合、そのリクエストは失敗し、リトライされません。これは、現在使用している jira ライブラリのバージョンの制限です。

### 保守的な値が重要な理由

**重要**: これらの設定には保守的な (低い) 値を使用することをお勧めします。その理由は以下のとおりです。

1. **Celery タスクのブロッキング**: DefectDojo における JIRA の操作は、非同期の Celery タスクとして実行されます。タスクがリトライの遅延を待っている間、その Celery worker は他のタスクの処理をブロックされます。

2. **Worker プールの枯渇**: 複数の JIRA 操作が長い遅延でリトライしていると、Celery worker プールがすぐに枯渇し、(JIRA 関連に限らず) 他のタスクもキューに溜まって待機することになります。

3. **システムの応答性**: リトライの遅延が長いと、特に JIRA の障害時やレート制限が発生している間、システムが応答していないように見えることがあります。

JIRA のレート制限機能は新しいため、どのような設定がうまく機能したか、Slack や GitHub でぜひお知らせください。

## Jira と DefectDojo が同期していない

Jira がダウンしていたり、DefectDojo がダウンしていたり、webhook にバグがあったりすることがあります。このような場合、Jira は DefectDojo と同期しなくなることがあります。多数の issue でこの状況が発生している場合、手動での整合は現実的でないかもしれません。このようなシナリオのために、管理コマンド 'jira_status_reconciliation' が用意されています。

このコマンドはバックエンドへのアクセスを必要とするため、DefectDojo Pro の Cloud ユーザーは利用できません。代わりに、この問題については弊社サポートチームまでお問い合わせください。

{{< highlight bash >}}
usage: manage.py jira_status_reconciliation [-h] [--mode MODE] [--product PRODUCT] [--engagement ENGAGEMENT] [--dryrun] [--version] [-v {0,1,2,3}]

Reconcile finding status with JIRA issue status, stdout will contain semicolon seperated CSV results.
Risk Accepted findings are skipped. Findings created before 1.14.0 are skipped.

optional arguments:
  -h, --help            show this help message and exit
  --mode MODE           - reconcile: (default)reconcile any differences in status between Defect Dojo and JIRA, will look at the latest status change
                        timestamp in both systems to determine which one is the correct status
                        - push_status_to_jira: update JIRA status for all JIRA issues
                        connected to a Defect Dojo finding (will not push summary/description, only status)
                        - import_status_from_jira: update Defect Dojo
                        finding status from JIRA
  --product PRODUCT     Only process findings in this product (name)
  --engagement ENGAGEMENT
                        Only process findings in this product (name)
  --dryrun              Only print actions to be performed, but make no modifications.
  -v {0,1,2,3}, --verbosity {0,1,2,3}
                        Verbosity level; 0=minimal output, 1=normal output, 2=verbose output, 3=very verbose output
{{< /highlight >}}

これは、次のコマンドを使用して uwsgi の docker コンテナから実行できます:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation'
{{< /highlight >}}

DEBUG 出力は `-v 3` で取得できますが、その前に settings.dist.py または local_settings.py ファイルでロギングレベルを DEBUG に上げておく必要があります。

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation -v 3'
{{< /highlight >}}

コマンドの最後に、セミコロン区切りの CSV サマリーが出力されます。これは、標準出力をファイルにリダイレクトすることでキャプチャできます:

{{< highlight bash >}}
$ docker compose exec uwsgi /bin/bash -c 'python manage.py jira_status_reconciliation > jira_reconciliation.csv'
{{< /highlight >}}
