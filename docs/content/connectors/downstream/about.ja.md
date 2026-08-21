---
title: Downstream Connectors
weight: 1
audience: pro
aliases:
- /ja/en/share_your_findings/integrations
- /ja/issue_tracking/pro_integration/integrations/
---

**提供状況:** ダウンストリームコネクタは一般提供されており、Cloud・On-Premiseを問わずすべてのDefectDojo Proインスタンスで有効になっています。有効化の操作は不要で、Feature Flagsページにも表示されなくなりました。

ダウンストリームコネクタを使うと、検出事項や検出事項グループをチケット管理システムにプッシュし、セキュリティ対応をチームの既存の開発ワークフローに簡単に組み込むことができます。

サポートされているダウンストリームコネクタ:
- Azure Devops
- Bitbucket
- Freshservice
- GitHub
- GitLab Boards
- Jira
- Linear
- Opsgenie
- PagerDuty
- ServiceDesk Plus
- ServiceNow
- ServiceNow SecOps / Vulnerability Response
- Shortcut
- Zendesk

## ダウンストリームコネクタページを開く

ダウンストリームコネクタページは、サイドバーの **Import > Connectors > Downstream Connectors** から見つけることができます。

![image](images/integrators_3.png)

## ダウンストリームコネクタの設定

ダウンストリームコネクタは、3つの主要なコンポーネントで構成されます。

- **Integration Instance（統合インスタンス）**: DefectDojoがサードパーティ製システムとの接続に使用する主要な接続方式です。Instanceには、ラベル、接続先、認証情報など、ベンダーが要求するその他の情報が含まれます。
- **Issue Tracker Mapping（課題トラッカーマッピング）**: マッピング情報が保存される場所で、ベンダー内の特定の「プロジェクト」に接続するために必要な詳細を定義します。これらの詳細には、「プロジェクト」の名前またはID、DefectDojoの検出事項の深刻度・ステータスからベンダー側の「チケット」の対応フィールドへのマッピングが含まれます。複数の「プロジェクト」に検出事項をプッシュする場合は、複数のマッピングを設定できます。
- **Issue Tracker Assignment（課題トラッカー割り当て）**: DefectDojoの製品やエンゲージメントを特定のIssue Tracker Mappingに割り当てる場所で、製品/エンゲージメントごとに検出事項がベンダーシステムへどのようにプッシュされるかを定義するオプションがあります。

これらのコンポーネントは階層構造になっています。各 **Instance** は1つ以上の **Mapping** を持ち、各Mappingはさらに1つ以上の **Tracker Assignment** を持ちます。

![image](images/integrators_2.png)

## 検出事項と検出事項グループのプッシュ

これらのコンポーネントを設定すると、検出事項や検出事項グループを手動または自動の2つの方法で、指定したIssue Trackerに送信できます。

- **手動**: Issue Tracker Mappingが割り当てられた製品/エンゲージメントに含まれる検出事項や検出事項グループには、「Push to Integrator」オプションが表示されます。これを実行すると、対応する検出事項/検出事項グループの情報を含むIssueがIssue Tracker上に作成されます。Push to Integratorは、既存のIssueを更新する際にも使用できます。

### 検出事項の自動プッシュ

検出事項は自動的にプッシュすることも可能で、その方法は **Issue Tracker Assignment** によって決まります。オプションは次の4つです。

- **Only Explicitly Publish Changes to Target**: このオプションを選択すると、割り当てられた製品またはエンゲージメントでの自動的な動作がすべて無効になります。検出事項や検出事項グループをプッシュする唯一の方法は、上記の通り明示的な操作のみになります。
- **Automatically Link New Finding to Target**: 割り当てられた製品またはエンゲージメントで新しい検出事項や検出事項グループが**作成**されると、DefectDojoは自動的にそのオブジェクトをIssue Trackerにプッシュします。作成後は、手動でPush to Integratorを実行しない限り、これらの検出事項や検出事項グループは更新されません。
- **Automatically Update Existing Link on Finding Edit**: 割り当てられた製品またはエンゲージメントで検出事項や検出事項グループが**更新**されると、既にリンクが手動で作成済みの場合、自動的にそのオブジェクトをIssue Trackerにプッシュします。
- **Automatically Link New and Update Existing Link on Finding Edit**: 割り当てられた製品またはエンゲージメントで検出事項や検出事項グループが作成**または**更新されると、自動的にそのオブジェクトをIssue Trackerにプッシュします。

#### プッシュフィルター

各Issue Tracker Assignmentでは、**自動的に**プッシュされる検出事項を任意で絞り込むことができます。

- **Minimum Severity（最小深刻度）**: 選択した深刻度以上の検出事項のみ、自動的にチケットを作成します。空欄のままにすると、すべての深刻度が対象になります。
- **Active findings only（アクティブな検出事項のみ）**: アクティブな検出事項のみ自動的にチケットを作成し、割り当てが最初に確認した時点で既に緩和済み・誤検知・リスク受容済みとなっているものはスキップします。

これらのフィルターは自動的な**作成**にのみ適用されます。すでにリンクされたチケットを持つ検出事項の更新は常に送信されるため、（クローズを含む）ステータス変更は引き続き反映されます。手動での **Push to Integrator** は常にフィルターを無視します。両方をデフォルトのままにしておくと、すべての検出事項をプッシュする従来の動作が維持されます。

#### 複数の製品への割り当て

Issue Tracker Assignmentは、単一の製品またはエンゲージメントを対象とします。複数の資産をカバーするには、製品(またはエンゲージメント)ごとに1つのAssignmentを作成してください。資産ごとにベンダー側のフィールドを変える必要がある場合 — 例えば異なるServiceNowの **Assignment group** や **Assigned to**、あるいは別のJiraプロジェクトなど — は、資産ごとに個別のIssue Tracker Mapping(それぞれ独自のCustom Field Mappingsを持つ)を作成し、各Assignmentを対応するMappingに向けてください。

## Issue Trackerチケットの表示

検出事項や検出事項グループの表示・一覧表示時、「Integrator Tickets」列の下に一連のアイコンとしてIssue Trackerチケットが表示されます。

左から順にアイコンは以下の通りです。

- **Integration Type（統合タイプ）**: チケットが関連付けられているIssue Trackerの種類
- **Ticket ID（チケットID）**: Issue Trackerで定義された、チケットのID
- **Ticket Link（チケットリンク）**: Issue Trackerで定義された、チケットへの直接リンク
- **Changelog（変更履歴）**: Issue Trackerチケットが検出事項または検出事項グループに関連付けられた日時、およびDefectDojoがチケットに最後に変更を加えた日時

![image](images/integrators_1.png)

## ベンダー固有の要件

各ベンダーには、DefectDojoがどのように連携する必要があるかについて、それぞれ異なる要件があります。これは認証方式、「プロジェクト」ごとの追加フィールド、深刻度/ステータスのマッピングなどの形をとる場合があります。

要件の完全な一覧については、以下のベンダー別ページを開いてください。

- [Azure Devops](/connectors/toolreference/azure_devops_boards/)
- [Bitbucket](/connectors/toolreference/bitbucket/#downstream-connector)
- [Freshservice](/connectors/toolreference/freshservice/)
- [GitHub](/connectors/toolreference/github/#downstream-connector)
- [GitLab Boards](/connectors/toolreference/gitlab/#downstream-connector)
- [Jira](/connectors/toolreference/jira/)
- [Linear](/connectors/toolreference/linear/)
- [Opsgenie](/connectors/toolreference/opsgenie/)
- [PagerDuty](/connectors/toolreference/pagerduty/)
- [ServiceDesk Plus](/connectors/toolreference/servicedesk_plus/)
- [ServiceNow](/connectors/toolreference/servicenow/)
- [ServiceNow SecOps / Vulnerability Response](/connectors/toolreference/servicenow_secops/)
- [Shortcut](/connectors/toolreference/shortcut/)
- [Zendesk](/connectors/toolreference/zendesk/)

## エラー処理とデバッグ

ダウンストリームコネクタでは、接続性、認証、権限などさまざまな理由でエラーが発生することがあります。こうしたエラーのデバッグを支援するため、各Issue Tracker Mappingには、エラーの発生日時、発生理由、プッシュに失敗した検出事項または検出事項グループを一覧表示するエラーテーブルが用意されています。

これらのエラーは、All Issue Tracker Mappings & Assignmentsページの ⚠️ Total Errors 列で確認できます。

![image](images/integrators_4.png)

Total Errorsのエントリをクリックすると、このダウンストリームコネクタに関連するエラーの詳細な説明が記載されたページに移動します。

### すべての失敗を一箇所で確認する

マッピングごとのエラーテーブルは、1つのダウンストリームコネクタのみを対象としています。[Diagnostics](/admin/diagnostics/pro__diagnostics/)は、アップストリームコネクタ、インポート、Jira、SSO、ルールエンジンなど、インスタンス上の他のすべての統合の試行とあわせて、それらすべてを対象とし、同じフィルタリングと並べ替えをすべてに対して行えます。

次のように、1つのマッピングの範囲を超えた疑問があるときに利用してください。

* 失敗ではなく**完了しなかった**試行 — 何もエラーが発生していないため、どのエラーテーブルにも報告されません
* ある失敗が1つの統合に固有のものか、複数にまたがって発生しているものか
* 誰が、あるいは何が、どの設定に対して試行を発生させたか

エラー内に記載された認証情報は、行が保存される前に除去され、完全な技術的詳細はスーパーユーザーのみに制限されます。

## ダウンストリームコネクタページのレイアウト

ダウンストリームコネクタは **Configured Connectors** と **Available Connectors** の2つのセクションに分かれて一覧表示され、それぞれ見出しの横に表示件数を添えてアルファベット順に並びます。1つのツールに対して複数の設定を保持できます。それぞれは独自のタイルとなり、`<Tool> - <label>` というタイトルでラベル順に並びます。DefectDojo Pro Cloud上の **Request Downstream Connector** タイルはカウントされません。
