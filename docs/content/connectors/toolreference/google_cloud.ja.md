---
title: "Google Cloud"
description: "DefectDojo で Google Cloud の Upstream Connector をセットアップする方法"
weight: 67
audience: pro
---
Google Cloudコネクタは**アセットコネクタ**です。Google Cloudのリソース階層を読み取り、**project**ごとにDefectDojoのアセットを作成し、そのprojectが属するfolderによってOrganizationsにグループ化します。folderもそれぞれアセットになるため、organization、folder、projectは、Cloud consoleで見えるのと同じツリーとしてDefectDojo上にも表示されます。検出事項はインポートされません。

**ご注意ください:** このコネクタがインポートするのはprojectの**インベントリ**のみです。Security Command Centerの検出事項をインポートするには、別途用意された[Google Cloud Security Command Center](/connectors/toolreference/google_cloud_scc/)コネクタを使用してください。この2つは互いに独立しており、併用することを前提に設計されています。このコネクタが作成するprojectは、SCCの検出事項が届くのと同じアセットであるため、両方を実行しても重複は発生しません。

#### Prerequisites

コネクタはGoogleの**サービスアカウント**で認証を行い、階層のメタデータ(folderとprojectの名前、id、ライフサイクルの状態、ラベル)のみを読み取ります。リソースの中身や検出事項は読み取りません。

1. Google Cloudでサービスアカウントを作成します。DefectDojo専用のアカウントを作成することをお勧めします。
2. インポートしたいorganizationまたはfolderに対して、**Browser**ロール(`roles/browser`)を付与します。階層の走査には`resourcemanager.folders.list`と`resourcemanager.projects.list`が必要です。カスタムロールにはさらに`resourcemanager.folders.get`と`resourcemanager.organizations.get`も含めてください。含めない場合、最上位のAssetは表示名ではなくリソースIDで命名されます。 アカウントにorganizationがない場合、ロールを付与する親リソースは存在しません。インポートしたい各projectに`roles/browser`を付与してください。
3. 設定するスコープの**最上位**でロールを付与してください。コネクタはサブツリー全体を走査するため、読み取れないfolderが1つでもあると、部分的なインベントリを黙ってインポートするのではなく、同期が失敗します。
4. サービスアカウントの**JSONキー**を作成してダウンロードします。
5. サービスアカウントを所有するprojectで**Cloud Resource Manager API**(`cloudresourcemanager.googleapis.com`)を有効にします。

#### Connector Mappings

1. 標準以外のエンドポイントを使用しない限り、**Location**フィールドはデフォルトの`https://cloudresourcemanager.googleapis.com`のままにします。
2. **Parent Resource**フィールドに、インポートしたい階層のルートを入力します: `organizations/{id}`または`folders/{id}`。単一のprojectは階層ではないため、`projects/{id}`はここでは使用できません。単一projectのスコープにはGoogle Cloud SCCコネクタを使用してください。 アカウントにorganizationがない場合は、このフィールドを空のままにしてください。コネクタはサービスアカウントが読み取れるすべてのprojectを、folder階層なしのフラットな一覧としてインポートします。
3. サービスアカウントの**JSONキー**ファイルの内容全体を**Service Account Key**フィールドに貼り付けます。

parentの配下にある`ACTIVE`状態のすべてのfolderとprojectがRecordになります。各projectのRecordはその**project ID**にちなんで名付けられ、DefectDojoでのOrganizationは、そのprojectが属するfolder(folderの直下にある場合はGoogle Cloudのorganization)になります。

Google Cloudでprojectを削除すると`DELETE_REQUESTED`状態になり、インポート対象から外れます。そのため、対応するRecordは削除されるのではなく、次回の同期時に`MISSING`としてフラグが付けられます。DefectDojoがアセットを黙って削除することはありません。folderを削除した場合も同様です。

Recordが一度マッピングされると、このコネクタはそのメタデータを二度と更新しません。Google Cloudでfolderの名前を変更したり、projectを別のfolderに移動したりしても、DefectDojoには古い名前や古いfolderが表示されたままになります。

#### Working alongside the Google Cloud SCC connector

どちらのコネクタも同じ方法でprojectを識別し、どちらもそのアセットをproject IDにちなんで名付けます。そのため、このコネクタを先に実行した場合、SCCの検出事項はこのコネクタが作成したアセットに届きます。SCCを先に実行した場合は、このコネクタがそれらのアセットを引き継ぎ、folderの階層をその周りに追加します。二重にマッピングする必要はありません。

Organizationについても同じ規則が適用されます。このコネクタがアセットを作成した場合、そのOrganizationはprojectが属するfolderになります。Google Cloud SCCコネクタが先にアセットを作成した場合は、そのアセットは既存のOrganizationを保持し、このコネクタはfolderの階層を追加するだけです。

例外が1つあります。organizationレベルのポリシー検出事項など、どのprojectにも属さないSCCの検出事項は、別のアセットに届きます。そのアセットはGoogle Cloud SCCコネクタが設定済みの親リソースに対して作成するもので、このコネクタが作成するorganizationやfolderのアセットではありません。両方のコネクタを実行する場合、これらの検出事項のために1つ追加のアセットができることを想定してください。
