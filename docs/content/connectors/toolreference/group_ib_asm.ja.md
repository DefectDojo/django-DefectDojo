---
title: "Group-IB ASM"
description: "DefectDojo で Group-IB ASM の Upstream Connector をセットアップする方法"
weight: 68
audience: pro
---
Group-IB ASM(Attack Surface Management)コネクタは、Group-IB ASM REST APIを使用して、外部の攻撃対象領域の**issue**(検出事項)をDefectDojoに取り込みます。DefectDojoは各Group-IBの**company/tenant**を個別のRecordとして検出し、そのcompanyのissueをスケジュールに基づいて増分的にインポートします。各issueが関連するアセット(ドメイン、IP、またはURL)は、生成された検出事項に**Endpoint**として付加されます。

#### Prerequisites

Group-IB ASMのログイン情報とAPIキーが必要です。自動化された操作を手動のチーム操作と区別できるよう、DefectDojo専用のサービスアカウントを作成することをお勧めします。

APIキーを生成するには:

1. Group-IB Attack Surface Managementを開き、左下の**Help**をクリックして**API**を選択します。
2. (右上、ユーザー名の下にある)**Generate API Key**をクリックします。
3. SSOパスワードを入力して**Next**をクリックし、次に**Copy token**をクリックします。
4. キーをシークレットマネージャーに保管し、定期的なローテーションを計画してください。

#### Connector Mappings

Group-IB ASMはHTTP Basic認証で認証を行います。ユーザー名はASMのログイン情報、パスワードはAPIキーです。**両方の値が必要です** — APIキーだけでは十分ではありません。

1. **Location**フィールドに`https://asm.group-ib.com`を入力します。これはすべてのGroup-IB ASMテナントで共通です。
2. **Username**フィールドにASMのログイン情報(通常はメールアドレス)を入力します。
3. **API Key**(Secret)フィールドにAPIキーを入力します。
4. 必要に応じて**Minimum Severity**を設定し、インポートする検出事項を制限できます。選択した深刻度を下回る検出事項はインポートされません。

DefectDojoは各Group-IBの**company**をcompany IDを識別子として個別のRecordにマッピングします。最初のSyncでは、DefectDojoは最近のissue履歴をバックフィルします。以降のSyncは増分的で、前回のSync以降に変更されたissueのみを(各issueの最新の`lastSeen`タイムスタンプで追跡して)取り込みます。

#### Scoping to a single company (optional)

デフォルトでは、コネクタはお使いのAPI資格情報でアクセス可能なcompanyを(ASMの`clients`エンドポイント経由で)自動的に検出し、company一つにつき一つのRecordを作成します。これが推奨のセットアップであり、追加の設定は不要です。

`clients`エンドポイントがお使いのテナントで利用できない場合(たとえばパートナー/MSPアカウントに制限されている場合など)、コネクタの設定でツール固有フィールド`company_id`にそのcompanyの**company ID**を指定することで、単一のcompanyにスコープを限定できます。`company_id`が設定されている場合、DefectDojoはcompanyを列挙する代わりにそのcompanyを直接使用します。自動検出を使用するには未設定のままにしてください。

詳細については、Group-IB ASM REST APIマニュアル(製品内の**Help → API**から利用可能)を参照してください。
