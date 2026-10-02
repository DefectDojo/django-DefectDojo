---
title: Jira
description: Jira連携の利用方法
weight: 2
audience: opensource
aliases:
- /ja/issue_tracking/jira/os__jira_guide/
---

DefectDojoのJira連携を使用すると、検出事項のデータを1つ以上のJiraスペースにプッシュできます。これにより、DefectDojoを標準的な開発ワークフローに組み込むことができます。以下はその活用例です。

* AppSecチームは、開発者が使用するJiraスペースへ検出事項を選択的にプッシュし、通常の開発作業と並行して問題の修正を適切に優先順位付けできます。このボード上の開発者はDefectDojoにアクセスする必要がなく、すべての作業を1か所にまとめておけます。
* DefectDojoは、AppSecチームが使用する双方向のJiraスペースにすべての検出事項をプッシュし、問題の検証作業を分担できるようにできます。このボードはDefectDojoと同期状態を保ち、複雑な修正ワークフローを可能にします。
* DefectDojoは、個別の製品やエンゲージメントから、それぞれ別のJiraスペースへ検出事項を選択的にプッシュし、適切なコンテキストを保つことができます。

# Jiraのセットアップ

Jiraのセットアップには、以下の手順が必要です。
1. システム設定でJira連携を有効にします。有効にするまで、それ以外のJira関連の設定はDefectDojo全体で非表示になります。
2. Jiraインスタンスを接続します。ユーザー名/パスワード、またはAPIトークンのいずれかを使用します。複数のインスタンスをリンクできます。
3. そのJiraインスタンスをDefectDojo内の1つ以上の製品またはエンゲージメントに追加します。
4. 双方向同期を使用したい場合は、DefectDojoに更新を送信するJira Webhookを作成します。

## ステップ1: システム設定でJira連携を有効にする

Jira連携はデフォルトでオフになっており、オフの間はDefectDojoがインターフェース上の他のすべてのJira関連コントロールを非表示にします。これが最初に設定すべき項目であり、有効化するまで以下の手順はいずれも利用できません。

連携が無効な間、サイドバーには ⚙️ **Configuration \> JIRA** の項目が表示されないため、Jiraインスタンスを追加する場所がありません。

![image](images/jira-config-menu-hidden-os.png)

### 連携を有効にする

1. DefectDojoのサイドバーから ⚙️ **Configuration \> System Settings** に移動します。
​
2. **Enable JIRA integration** にチェックを入れます。
​
3. 連携を有効にすると同時に **Jira webhook secret** が必須になります。フィールド横の 🔄 アイコンをクリックして生成してください。シークレットを入力せずにフォームを送信すると、*「This field is required when enable Jira Integration is True」* というエラーで拒否されます。

![image](images/jira-webhook-secret-required-os.png)

このシークレットは、Jiraが送信先とするWebhook URL(`https://<YOUR DOJO DOMAIN>/jira/webhook/<SECRET>`)の一部であるため、生成された値は認証情報として扱ってください。Jiraに渡す必要があるのは、[ステップ4](#step-4-configure-bidirectional-sync-jira-webhook)で双方向同期を設定する場合のみです。ここで生成するのは単にフォームの要件を満たすためです。

4. **Submit** をクリックします。サイドバーに ⚙️ **Configuration \> JIRA** が表示されるようになります。

![image](images/jira-enable-system-settings-os.png)

### この設定が制御するもの

**Enable JIRA integration** を有効にすることで、残りのJira関連インターフェースが表示されるようになります。有効にすると、以下が利用できます。

* Jiraインスタンスの追加・編集を行う ⚙️ **Configuration \> JIRA** ページ
* 製品(アセット)編集フォームおよびエンゲージメント編集フォームにある、製品またはエンゲージメントをJiraスペースにリンクするための **JIRA** セクション
* 検出事項、検出事項グループ、一括編集フォームにある **Push to Jira** コントロール、および検出事項・エンゲージメント・製品の一覧にあるJira列とフィルター

例えば、**JIRA** セクションは連携が有効になって初めて、製品編集フォームの下部に表示されます。

![image](images/jira-asset-settings-visible-os.png)

この設定はUI以外の部分でも連携を制御します。オフの間は、DefectDojoは検出事項をJiraにプッシュせず(APIを通じて送信される `push_to_jira` リクエストも含む)、受信したJira Webhookも無視されます。

システム設定ページに残る他のJira関連フィールド(**Enable JIRA web hook**、**Jira minimum severity**、**Jira labels**、**Add vulnerability Id as a JIRA label**)は、連携のオン/オフにかかわらず表示され続けますが、連携が有効になるまでは効果を持ちません。

## ステップ2: Jiraインスタンスを接続する

連携を有効にしたら、次はDefectDojoのJira連携をセットアップするためにJiraインスタンスを接続します。なお、Jira Service Managementは現時点ではサポートされていません。

#### Jira側で必要な情報

Atlassianは、Jira CloudとJira Data Centerとで異なる認証方式を採用しています。

**Jira Cloud** の場合、以下が必要です。
* Jira URL(例: https://yourcompany.atlassian.net/)
* Jiraインスタンス上で課題を作成・更新できる権限を持つアカウント。次のいずれかです。
    * 標準的な **ユーザー名/パスワード** の組み合わせ
    * **ユーザー名/APIトークン** の組み合わせ

**Jira Data Center(またはServer)** の場合、以下が必要です。
* Jira URL(例: https://jira.yourcompany.com)
* Jiraインスタンス上で課題を作成・更新できる権限を持つアカウント。次のいずれかです。
    * 標準的な **ユーザー名/パスワード** の組み合わせ

オプションとして、以下をマッピングできます。
* 検出事項の再オープンとクローズをトリガーするJiraのトランジション
* 検出事項にリスク受容済みや誤検知のステータスを適用できるJiraの解決(Resolution)(任意)

複数のJiraスペースを、単一のJiraインスタンス接続で扱うことができます。ただし、DefectDojoが使用するJiraのアカウント/トークンが、対象のJiraスペースで課題を作成できる権限を持っている必要があります。

### Jiraインスタンスを追加する

1. [ステップ1](#step-1-enable-the-jira-integration-in-system-settings)の説明通り、システム設定で **Enable JIRA integration** にチェックが入っていることを確認します。有効になるまで、サイドバーに ⚙️ **Configuration \> JIRA** オプションは表示されません。
​
2. DefectDojoのサイドバーから ⚙️ **Configuration \> JIRA** ページに移動します。
​
![image](images/Connect_DefectDojo_to_Jira.png)

3. 現在DefectDojoにリンクされているすべてのJiraスペースの一覧が表示されます。新しいプロジェクト設定を追加するには、レンチアイコンをクリックし、**Add Jira Configuration (Express)** または **Add Jira Configuration** のいずれかを選択します。

#### Add Jira Configuration (Express)

Express方式は、スペースをより短時間でリンクするための方法です。単純に素早くJiraスペースを接続したいだけで、複雑なJiraワークフローを扱わない場合はExpress方式を使用してください。

![image](images/Connect_DefectDojo_to_Jira_2.png)

1. このJira設定にDefectDojo内で使用する名前を選びます。この名前は単にDefectDojo内でのインスタンス接続を示すラベルであり、Jira側のデータと一致させる必要はありません。
​
2. 自社のJiraインスタンスのURLを選択します。Jira Cloudを利用している場合は、`https://**yourcompany**.atlassian.net` のような形式になるはずです。
​
3. Jira用のユーザー名/パスワードのフィールドに、適切な認証方式の情報を入力します。
    * 標準的な **ユーザー名/パスワードによるJira認証** の場合、これらのフィールドにJiraのユーザー名と対応するパスワードを入力します。
    * **ユーザーのAPIトークン(Jira Cloud)** による認証の場合、パスワードフィールドにユーザー名と対応する **APIトークン** を入力します。
​
4. Jiraで課題を作成する際のデフォルトの課題タイプを選択します。選択肢は、標準的なJira課題タイプである **Bug、Task、Story**、**Epic**、およびカスタム課題タイプである **Spike**、**Security** です。これら以外の課題タイプを使用したい場合は、[support@defectdojo.com](mailto:support@defectdojo.com) までご連絡ください。
​
5. 課題テンプレートを選択します。これにより、Jiraで課題が作成される際の課題の説明(Description)の内容が決まります。

2種類のテンプレートがあります。
- **Jira\_full**: すべての検出事項の情報をJira課題に含めます
- **Jira\_limited**: より少ない量の検出事項情報とメタデータのみを含めます

このフィールドを空欄のままにした場合、デフォルトで **Jira\_full** が使用されます。

6. 課題上でこの解決(Resolution)がトリガーされたときに、検出事項のステータスを「リスク受容済み」に変更するJiraの解決タイプを1つ以上選択します。この自動化を使用しない場合は、このフィールドを空欄のままにしてください。
​
7. 課題上でこの解決(Resolution)がトリガーされたときに、検出事項のステータスを「誤検知」に変更するJiraの解決タイプを1つ以上選択します。この自動化を使用しない場合は、このフィールドを空欄のままにしてください。
​
8. SLA通知をJira課題へのコメントとして送信するかどうかを決定します。
​
9. 検出事項をJiraと自動的に同期するかどうかを決定します。これを有効にすると、Jira課題は関連する検出事項と自動的に同期状態を保ちます。有効にしない場合、課題がJiraで作成された後に検出事項に加えた変更は手動でプッシュする必要があります。
​
10. Issueキーを選択します。Jiraでは、これは課題に紐づく文字列です(例: **EXAMPLE-123** という課題での **'EXAMPLE'** という単語)。Issueキーが分からない場合は、Jiraスペースで新しい課題を作成してください。以下のスクリーンショットでは、Jiraスペースの課題キーが **DEF** であることが分かります。
​
![image](images/Connect_DefectDojo_to_Jira_3.png)
​
11. **Submit** をクリックします。DefectDojoは自動的にJira内の適切なマッピングを探し、設定に追加します。これで、この設定をDefectDojo内の1つ以上の製品にリンクする準備が整いました。

#### Add Jira Configuration (Standard)

標準のJira設定では、Jiraのマッピングや連携をより精密に制御するための追加手順がいくつか加わります。この設定は、Express方式で作成された場合でも、後から変更できます。
​
### 追加のフォームオプション

* **Epic Name ID:** Jira内に複数のEpicタイプがある場合、Jiraのフィールド仕様からIDを調べて、使用したいものを指定できます。
​
'Epic name id' を取得するには、`https://<YOUR JIRA URL>/rest/api/2/field` にアクセスし、Epic Nameを検索してください。`number` に含まれる数字をコピーして、ここに貼り付けます。
​ ​
* **Reopen Transition ID:** 課題を再オープンする特定のJiraトランジションを指定したい場合、ここにトランジションIDを指定できます。Express方式のJira設定を使用している場合、DefectDojoが自動的に適切なトランジションを見つけてマッピングを作成します。
​
JiraインスタンスのIDを調べるには、`https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` にアクセスしてください。それをReopen Transition IDフィールドに貼り付けます。
​
* **Close Transition ID:** 課題をクローズする特定のJiraトランジションを指定したい場合、ここにトランジションIDを指定できます。**Express Jira Configuration** を使用している場合、DefectDojoが自動的に適切なトランジションを見つけてマッピングを作成します。
​
JiraインスタンスのIDを調べるには、`https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` にアクセスしてください。それをClose Transition IDフィールドに貼り付けます。
​
* **Mapping Severity Fields:** 各Jira課題には優先度(Priority)が紐づいており、DefectDojoは検出事項の深刻度に基づいて自動的にこれを割り当てます。情報、低、中、高、重大の各深刻度についてマッピングしたい優先度の名前を入力してください。

* **Finding Text** - 作成される各課題に追加の定型文を加えたい場合、ここにそのテキストを入力できます。これはJira側の特定のフィールドにマッピングされるテキストではなく、課題の説明に追加されるテキストです。例えば「**Created by DefectDojo**」のようなものです。

コメント(Jira側)とメモ(DefectDojo側)は同期させることができます。この設定は、Jira設定が製品に追加された後、**製品編集** フォームから有効にできます。

## ステップ3: 製品またはエンゲージメントをJiraに接続する

DefectDojo内の各製品またはエンゲージメントには、検出事項がどのようにJira課題へ変換されるかを制御する独自の設定があります。ここから、対応するJiraスペースを決定し、課題・Epic・ラベルなどのJiraメタデータを作成する際のデフォルトの動作を設定できます。

### 製品またはエンゲージメントにJiraを追加する

クラシックUIでは、製品編集フォームまたはエンゲージメント編集フォームを開くことでJiraの設定が見つかります。ページ上の **Settings** の下にある「**📝 Edit**」ボタンです。

![image](images/Add_a_Connected_Jira_Project_to_a_Product.png)

#### Jira設定の一覧

Jiraの設定は、製品設定ページの下部近くにあります。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_2.png)

#### Jira Instance

組織内の別々の製品やチーム向けに複数のJiraインスタンスをセットアップしている場合、DefectDojoが課題を作成すべきJiraスペースを指定できます。ドロップダウンメニューからプロジェクトを選択してください。

このメニューにJiraインスタンスが1つも表示されない場合は、DefectDojoのグローバルJira設定(yourcompany.defectdojo.com/jira)でそれらのプロジェクトが接続されていることを確認してください。

#### Project key

これは、DefectDojoで使用したいスペースのキーです。特定のプロジェクトのスペースキーは、URL内、またはスペース設定内の「Space key」の項目で確認できます。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Issue template

ここでは、Jiraに送信するDefectDojoのメタデータの量を決定できます。以下の2つのオプションから選択します。

* **jira\_full**: DefectDojoのすべてのパラメーター(完全な説明、CVE、深刻度など)を課題に記録します。Jira内でDefectDojoにアクセスできない担当者がその課題に取り組んでいる場合など、完全な検出事項のコンテキストが必要な場合に有用です。

以下は **jira\_full** の課題の例です。
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira\_limited:** 課題にはDefectDojoへのリンク、製品/エンゲージメント/テストへのリンク、Reporterフィールド、Environmentフィールドのみが記録されます。それ以外のフィールドはDefectDojo内でのみ管理されます。主にDefectDojo上で作業しており、Jira側で検出事項の全体像を必要としない担当者がその課題に取り組んでいる場合など、Jira内で完全な検出事項のコンテキストを必要としない場合に有用です。

​以下は **jira\_limited** の課題の例です。​

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

Jiraスペースをコンポーネントで管理している場合、ここでDefectDojo用の適切なコンポーネントを割り当てられます。複数のコンポーネントを割り当てるには、カンマ区切りのリストを入力してください(例: `Security, DevSecOps`)。各値は個別のコンポーネントとしてJiraに送信されます。

**Custom fields**

DefectDojoの課題でカスタムフィールドを使用する必要がない場合は、このフィールドを「null」のままにしておいて構いません。

ただし、Jiraスペースの設定で新規課題にカスタムフィールドの使用が **必須** とされている場合は、これらのマッピングをハードコードする必要があります。

**Jira Cloudでは、アプリ内で直接デフォルトのカスタムフィールド値を作成できるようになりました。設定方法の詳細については、[Atlassianのカスタムフィールドに関するドキュメント](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/)を参照してください。**

DefectDojoは課題ごとに異なるメタデータをカスタムフィールドとして送信することはできず、送信できるのはデフォルト値のみである点に注意してください。この項目は、Jiraスペース内のすべての課題にこれらのカスタムフィールドが **存在することが必須** である場合にのみ設定してください。

カスタムフィールドの利用を開始するには、**[こちらのガイド](#custom-fields-in-jira)** を参照してください。

**Jira labels**

Jiraで課題を作成する際に付与したい関連ラベルを選択します(例: **DefectDojo**、**YourProductName..**)。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

Jira上でのデフォルトの担当者名です。空欄のままにした場合、DefectDojoは課題作成時にJiraスペースのデフォルトの動作に従います。

### 追加のフォームオプション

#### Enable Connection With Jira Space

Jira連携は、関連する課題が作成されていない場合に限り、インスタンスから削除できます。課題が作成済みの場合、DefectDojoからJiraインスタンスを完全に削除する方法はありません。

ただし、製品レベルで無効化することでJira連携を無効にすることはできます。これにより、DefectDojoが作成した既存のJiraチケットが削除・変更されることはありませんが、それ以降の更新は無効になります。

#### Add Vulnerability Id as a Jira label

これを使用すると、脆弱性IDのデータを自動的にJiraのラベルとして追加できます。脆弱性IDは各セキュリティツールから検出事項に追加されるもので、共通脆弱性識別子(CVE)IDである場合も、それを報告したツール固有の別の形式である場合もあります。

#### Enable Engagement Epic Mapping (For Products)

DefectDojoにおいて、エンゲージメントは一連の作業のまとまりを表します。各エンゲージメントには1つ以上のテストが含まれ、各テストには修正が必要な1つ以上の検出事項が含まれます。JiraのEpicも同様の考え方で機能するため、このチェックボックスを使うと、エンゲージメントをEpicとしてJiraにプッシュできます。

* DefectDojo上のエンゲージメント - 下部に3件の検出事項が表示されている点に注目してください。
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* 同じエンゲージメントがJiraにプッシュされるとEpicになる様子 - エンゲージメントの検出事項も併せてプッシュされ、そのエンゲージメント内に子課題(Child Issues)として存在します。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push All Issues

チェックを入れると、DefectDojoはアクティブかつ検証済みのすべての検出事項を自動的に課題としてJiraにプッシュします。チェックを外したままにすると、すべての検出事項を手動でJiraにプッシュする必要があります。

#### Push Notes

有効にすると、Jira側のコメントがDefectDojo内の該当する検出事項のメモ(スクリーンショット参照)に反映されるようになり、逆方向についても、検出事項のメモが対応するJira課題にコメントとして追加されるようになります。

#### Send SLA Notifications As Comments

有効にすると、DefectDojoのサービスレベルアグリーメント(SLA)のルールに違反した課題に、その旨を示すコメントがJira課題に追加されるようになります。これらのコメントは、課題が解決されるまで毎日投稿され続けます。

サービスレベルアグリーメントは、DefectDojoの **Configuration \> SLA Configuration** から設定でき、各製品に割り当てられます。

#### Send Risk Acceptance Expiration Notifications As Comment?

有効にすると、関連するDefectDojoのリスク受容が期限切れになった課題に、その旨を示すコメントがJira課題に追加されるようになります。これらのコメントは、課題が解決されるまで毎日投稿され続けます。

### エンゲージメントレベルのJira設定

そのため、同じ製品内のエンゲージメントであっても、それぞれ異なるJira設定を持つことができます。デフォルトでは、エンゲージメントは「**製品からJira設定を継承する**」状態になっており、これは配下にある製品と同じJira設定を共有することを意味します。

ただし、エンゲージメントの **Product Key**、**Issue Template、Custom Fields、Jira Labels、Default Assignee** を、デフォルトの製品設定とは異なる内容に変更することができます。

このページには、**エンゲージメント編集** ページ(**your-instance.defectdojo.com/engagement/[id]/edit**)からアクセスできます。

エンゲージメント編集ページは、エンゲージメントページで、エンゲージメントの説明の横にある ☰ メニューをクリックすることで見つけられます。

![image](images/Creating_Issues_in_Jira_5.png)

## ステップ4: 双方向同期を設定する: Jira Webhook

Jira連携では、Webhookによる双方向同期が可能です。DefectDojoは固有のアドレスでJiraの通知を受信し、設定によっては、Jiraのコメントを検出事項側で受信したり、Jira経由で検出事項を解決済みにしたりできます。

### Jira Webhook URLの確認方法

Jira WebhookのURLは、DefectDojoのURLと、[ステップ1](#step-1-enable-the-jira-integration-in-system-settings)で生成した **Jira webhook secret** から構成されます。この両方は、⚙️ **Configuration \> System Settings** ページの **Jira webhook secret** フィールドの横に表示されます(ステップ1のスクリーンショットを参照してください)。

また、DefectDojoが受信したJiraの通知を処理できるようにするには、同じページで **Enable JIRA web hook** にもチェックを入れる必要があります。このチェックボックスまたは **Enable JIRA integration** のいずれかがオフになっている場合、受信したWebhookは無視されます。

### Jira Webhookの作成

1. `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**` にアクセスします。
2. 「Create a Webhook」をクリックします。
3. 「URL」というラベルのフィールドに次のように入力します: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`。Web Hook Secretは、前述の通り **Jira webhook secret** フィールドの横に表示されています。
4. 「Comments」の下で「Created」を有効にします。「Issue」の下で「Updated」を有効にします。
5. JiraインスタンスがDefectDojoインスタンスの使用するSSL証明書を信頼していることを確認してください。JIRA Cloudの場合、DefectDojo側は[グローバルに信頼された認証局によって署名された有効なSSL/TLS証明書](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)を使用している必要があります。

このWebhookを使用するために、Jira内でシークレットを別途作成する必要はありません。シークレットはDefectDojoのURLに組み込まれているため、完全なURLをJira Webhookのフォームにそのまま入力すれば十分です。

受信するWebhookリクエストはそのURL内のシークレットによって認証されるため、URL全体を認証情報として扱い、非公開に保ってください。

#### Webhookのテスト

DefectDojoの検出事項から作成された課題が1つ以上ある状態で、それらの検出事項のいずれかにコメントを追加することでWebhookをテストできます。そのコメントは、メモとしてJira Webhookに受信されるはずです。

これが正しく動作しない場合、Jiraインスタンス側のファイアウォールの問題でWebhookがブロックされている可能性があります。

* DefectDojoのファイアウォールルールには **Jira Cloud** 用のチェックボックスがあり、DefectDojoがJiraからのWebhookメッセージを受信できるようにするには、これを有効にする必要があります。

### 代替方法: Jira Automationを使用する(Send web request)

Jiraインスタンスの中には、`/plugins/servlet/webhooks` 配下のシステムWebhookを許可していないものがあります。例えば、その管理領域が制限されており、**Jira Automation** のルールのみが許可されている場合です。その場合でも、Automationの **Send web request** アクションを使い、同じDefectDojoのWebhookエンドポイントにPOSTすることで、同様の双方向同期を実現できます。

DefectDojoのWebhookエンドポイントは、`Content-Type: application/json` を伴い、URLパス内に有効なシークレットを含んだ任意のHTTP `POST` リクエストを受け付けます。リクエストがJiraのシステムWebhookの仕組みから発信されたものであることを **要求しない** ため、Automationの「Send web request」アクションはそのまま代替手段として機能します。

#### 前提条件

システムWebhookと同じ前提条件が適用されます。

* ⚙️ **Configuration \> System Settings** ページで、**Enable JIRA integration** と **Enable JIRA web hook** の両方にチェックが入っていること。
* そのページで、空でない **Jira webhook secret** が設定されていること。シークレットに使用できる文字は `A-Z`、`a-z`、`0-9`、`_`、`-` のみです。
* 検出事項(または検出事項グループ)が、すでにJiraの課題にリンクされていること。課題がDefectDojoの検出事項にリンクされていない場合でも、リクエスト自体は受け付けられます(HTTP `200`)が、処理は行われません。

#### DefectDojoがリクエストを処理する仕組み

* DefectDojoは、トップレベルの `webhookEvent` フィールドで処理を分岐します。処理されるのは `"jira:issue_updated"` と `"comment_created"` のみで、それ以外の値はリクエストとしては受け付けられますが無視されます。Automationはこのフィールドを自動的には追加しないため、リクエスト本文に自分で含める必要があります。
* そのため、リクエストの **Body** を **Custom data** に設定し、以下のJSONを指定してください。**Empty** および **Jira issue data** の本文オプションには必須の `webhookEvent` フィールドが含まれないため、DefectDojoはそれらを無視します。
* このエンドポイントは、更新が実際に適用されたかどうかにかかわらず、常にHTTP `200` を返します。成功・失敗はレスポンス本文とDefectDojoのログでのみ確認できます。Automationの監査ログ上の `200` は、それだけでは更新が検出事項に反映されたことの確証にはなりません。

#### ルール1 - Issue updated

次の内容でAutomationルールを作成します。

* **Trigger:** *Issue transitioned*(または、同期対象のフィールドが変化したときに発火する別のトリガー。例えばStatusに対する *Field value changed* など)。
* **Action:** *Send web request*
  * **Web request URL:** `https://<YOUR DOJO DOMAIN>/jira/webhook/<YOUR WEBHOOK SECRET>`
  * **HTTP method:** `POST`
  * **Web request body:** *Custom data*
  * **Headers:** `Content-Type: application/json`
  * **Custom data:**

```json
{
  "webhookEvent": "jira:issue_updated",
  "issue": {
    "id": "{{issue.id}}",
    "fields": {
      "updated": "{{issue.updated}}",
      "resolution": null,
      "status": { "statusCategory": { "key": "{{issue.status.statusCategory.key}}" } },
      "assignee": { "name": "{{issue.assignee.accountId}}", "displayName": "{{issue.assignee.displayName}}" }
    }
  }
}
```

課題更新に関する制約:

* `issue.id` は、課題キー(例: `PROJ-123`)ではなく、**Jiraの内部的な数値の課題ID**(`{{issue.id}}`)である必要があります。DefectDojoは、この数値IDによって更新対象の検出事項を特定します。
* `resolution` フィールドと `updated` フィールドは常に含まれている必要があります。`resolution` は `null` でも構いませんが、どちらかのフィールドが欠けている場合、リクエストは受け付けられ(`200`)ますが、処理は行われずに黙って無視されます。
* ステータスの同期と自動的な緩和処理は `status.statusCategory.key` によって制御され、Jira側の値は `new`(To Do)、`indeterminate`(In Progress)、`done`(Done)です。検出事項が緩和済みになるのは、課題が実際にクローズされた場合のみであり、単に何らかの解決(resolution)の値が存在するだけでは緩和済みにはなりません。

#### ルール2 - Issue commented

次の内容で2つ目のAutomationルールを作成します。

* **Trigger:** *Issue commented*
* **Action:** *Send web request* - ルール1と同じURL、メソッド、ヘッダー、*Custom data* の本文オプションを使用し、本文は以下の内容にします。

```json
{
  "webhookEvent": "comment_created",
  "comment": {
    "self": "https://<your-jira-host>/rest/api/2/issue/{{issue.id}}/comment/{{comment.id}}",
    "body": "{{comment.body}}",
    "updateAuthor": { "name": "{{comment.author.accountId}}", "displayName": "{{comment.author.displayName}}" }
  }
}
```

コメントに関する制約:

* `body` と `updateAuthor` の両方が含まれている必要があります。
* DefectDojoは対象の課題を `comment.self` のURL、具体的には `.../issue/<id>/comment/...` の部分に含まれる `<id>` から特定するため、`{{issue.id}}`(数値ID)がそこに含まれている必要があります。
* **ループ防止:** コメントの投稿者が、DefectDojo自身がコメントを投稿する際に使用しているJiraアカウントと一致する場合、DefectDojoはエコーループを避けるためそのコメントをスキップします。すべてのコメントを取り込みたい場合は、DefectDojoのJiraインスタンス設定で使用しているユーザーとは **別の** Jiraユーザーとして、Automationルールを実行してください。

#### スマート値に関する注意

上記に示したスマート値(`{{issue.id}}`、`{{issue.status.statusCategory.key}}`、`{{comment.author.accountId}}` など)は、Jira Cloudの標準的な名称ですが、インスタンスにより異なる場合があります。実際の運用を始める前に、Automationのペイロードプレビューを使用して、各スマート値が想定通りの値に解決されることを確認してください。

## Jira 連携のテスト

#### テスト1: 検出事項は正常に Jira へプッシュされるか

Jira 連携が正常に動作しているかをテストするには、DefectDojo で Jira と関連付けられている製品に新しい空の検出事項を追加します。**製品 > 検出事項 > 新規検出事項の追加**

任意のタイトル、深刻度、説明を入力し、「Finished」をクリックします。検出事項は、関連するすべてのメタデータとともに Jira の Issue として表示されるはずです。

Jira の Issue が正しく作成されない場合は、通知でエラーコードを確認してください。

* DefectDojo の Jira 設定に関連付けられた Jira ユーザーが、その Jira スペースで Issue を作成・更新する権限を持っていることを確認してください。

#### テスト2: Jira Webhook から DefectDojo への送信

Jira Webhook をテストするには、JIRA に Issue として存在している検出事項にメモを追加します(例えば、上記セクションで作成したテスト用の Issue)。

Webhook が正しく設定されていれば、そのメモが Jira 上で Issue へのコメントとして表示されるはずです。

正しく動作しない場合、Jira インスタンス側のファイアウォールが Webhook をブロックしている可能性があります。

* DefectDojo のファイアウォールルールには **Jira Cloud** 用のチェックボックスがあり、DefectDojo が Jira から Webhook メッセージを受信できるようにするには、これを有効にする必要があります。

## Jira との接続解除

Jira 連携は、関連する Issue が一つも作成されていない場合にのみ、インスタンスから削除できます。Issue が作成済みの場合、DefectDojo から Jira インスタンスを完全に削除する方法はありません。

ただし、製品レベルで Jira 連携を無効化することは可能です。**製品の編集**フォームで「Enable Connection With Jira Space」オプションのチェックを外してください。これにより、DefectDojo が作成した既存の Jira チケットが削除・変更されることはありませんが、以降の更新は無効になります。

# 検出事項の Jira へのプッシュ

## 検出事項の Jira へのプッシュ
JIRA マッピングを持つ製品は、検出事項を Issue として Jira にプッシュできます。これは次の2つの方法で管理できます。

* 検出事項ごとに手動で Issue として作成する。
* 製品で「**Push All Issues**」設定が有効になっている場合、検出事項は自動的にプッシュされる(これは **アクティブ** かつ **検証済み** の検出事項にのみ適用されます)。

さらに、個々の検出事項ではなく、検出事項グループを Jira にプッシュするオプションもあります。これにより、関連する複数の DefectDojo の検出事項をまとめた単一の Issue が作成されます。

### 検出事項を手動でプッシュする

1. DefectDojo の検出事項ページで、**JIRA** の見出しに移動します。検出事項がまだ JIRA に Issue として存在していない場合、JIRA の見出しの値は「**None**」になります。
​
2. **None** の値の隣にある矢印をクリックすると、新しい Jira Issue が作成されます。Issue がどの State で作成されるかは、チームのワークフローや DefectDojo との Jira 連携設定によって異なります。検出事項が表示されない場合は、ページを更新してください。
​
![image](images/Creating_Issues_in_Jira.png)

3. Issue が作成されると、DefectDojo は Jira のキーと Issue ID から構成されるリンクを作成します。このリンクの隣には赤いゴミ箱アイコンがあり、Jira から Issue を削除できます。
​
![image](images/Creating_Issues_in_Jira_2.png)

4. 矢印を再度クリックすると、Issue に加えられたすべての変更が Jira にプッシュされ、Jira の Issue が更新されます。検出事項が属する製品で「**Push All Issues**」設定が有効な場合、このプロセスは自動的に行われます。

### Jira のコメント

* Jira の Issue にコメントが追加されると、同じコメントが検出事項の **メモ** セクションに追加されます。
* 同様に、検出事項にメモが追加されると、そのメモは Jira の Issue にコメントとして追加されます。

### Jira のステータス変更

DefectDojo の Jira 設定には、検出事項のステータス変更をトリガーする2つの Jira トランジションの設定項目があります。

* Jira で **「Close」トランジション** が実行されると、関連する検出事項もクローズされ、DefectDojo 上で **非アクティブ** かつ **緩和済み** としてマークされます。DefectDojo はこの変更を検出事項ページの **Mitigated By** 見出しの下に記録します。
​
![image](images/Creating_Issues_in_Jira_3.png)

* Jira の Issue で **「Reopen」トランジション** が実行されると、関連する検出事項は DefectDojo 上で **アクティブ** に設定され、**緩和済み** のステータスは解除されます。

### Jira の Resolution をリスク受容・誤検知にマッピングする

Close / Reopen トランジションに加えて、Jira 設定には Jira の **Resolution** を DefectDojo の検出事項ステータスにマッピングするオプションのフィールドが含まれています。これらは **Add Jira Configuration (Express)** ワークフロー(手順6と7)の中で設定され、後から Jira 設定画面で編集することもできます。

* **Risk Accepted Finding Mapping Resolution** — Jira の Issue がこの Resolution でクローズされると、関連付けられた検出事項は DefectDojo で **リスク受容済み** になります。
* **False Positive Finding Mapping Resolution** — Jira の Issue がこの Resolution でクローズされると、関連付けられた検出事項は DefectDojo で **誤検知** になります。

#### ステータスと Resolution: よくある混同ポイント

これらのフィールドがマッピングするのは Jira の **Status** ではなく **Resolution** です。Status と Resolution は Jira における独立した2つの概念です。Status は Issue がワークフロー内のどこにあるか(Open、In Progress、Done など)を表し、Resolution はどのように解決されたか(Fixed、Won't Do、Duplicate、False Positive など)を表します。

よくある混同として、Jira のワークフロートランジションが Resolution を設定 *せずに* Status を「Done」に変更できてしまう点が挙げられます。この場合、DefectDojo の Resolution マッピングは発火せず、検出事項は上記で説明した標準の **「Close」トランジション** の動作により **緩和済み** としてマークされます(リスク受容済みや誤検知にはなりません)。

#### 前提条件: Jira ワークフロートランジションでの「Set issue resolution」ポストファンクション

Jira のワークフローエンジンは Resolution フィールドを自動的には設定しません。特定の Resolution で Issue をクローズするべき各トランジションには、そのトランジション自体に **Set issue resolution** ポストファンクションを設定する必要があります。このポストファンクションがない場合、Issue は新しい Status に移行しますが Resolution は空のままとなり、DefectDojo のマッピングは照合対象を持てません。

Jira の管理者は、**Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution** からこのポストファンクションを追加できます。

## 検出事項グループを Jira の Issue としてプッシュする

検出事項グループが有効になっている場合、検出事項ごとに個別の Issue を作成する代わりに、検出事項のグループを単一の Issue として Jira にプッシュできます。

ただし、検出事項グループに関連付けられた Jira の Issue は、DefectDojo から操作したり削除したりすることはできません。Jira インスタンス側から直接削除する必要があります。

### 検出事項グループを自動的に作成してプッシュする

Auto-Push To Jira が有効で、インポート時に Group By オプションが選択されている場合:

検出事項グループが正常に作成されている限り、個々の検出事項ではなく検出事項グループが Issue として自動的に Jira にプッシュされます。

![image](images/Creating_Issues_in_Jira_4.png)

## Jira のカスタムフィールド
<span style="background: rgba(243, 122, 78,0.5">DefectDojo は現在、Issue 固有の情報をこれらのカスタムフィールドに渡すことをサポートしていません。これらのフィールドは、Issue の作成後に Jira 側で手動で更新する必要があります。各カスタムフィールドは、DefectDojo からはデフォルト値でのみ作成されます。</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloud では現在、アプリ内で直接デフォルトのカスタムフィールド値を作成できるようになりました。設定方法の詳細については、[Atlassian のカスタムフィールドに関するドキュメント](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/)を参照してください。</span>

DefectDojo に組み込まれている Jira の Issue タイプ(**Bug、Task、Story**、**Epic**)は、追加設定なしでそのまま動作するように構成されています。DefectDojo のデータフィールドは、Jira の対応するフィールドに自動的にマッピングされます。デフォルトでは、DefectDojo は作成する新しい Issue に Priority、Labels、Reporter を自動的に割り当てます。

一部の Jira 構成では、Issue を作成する前に追加のカスタムフィールドを設定しておく必要があります。この手順に従うことで、DefectDojo → Jira 連携においてこれらのカスタムフィールドを考慮に入れ、Issue の作成を確実に成功させることができます。これらのカスタムフィールドは、DefectDojo から連携先の Jira インスタンスに送信されるすべての API 呼び出しに追加されます。

Jira でカスタムフィールドをまだ使用していない場合、この手順に従う必要はありません。

1. Jira でカスタムフィールドの名前を記録する(**Jira UI**)
2. 新しいカスタムフィールドの Key 値を特定する(Jira Field Spec エンドポイント)
3. Key 値を参照して、各カスタムフィールドで許容されるデータ形式を確認する(Jira Issue エンドポイント)
4. すべてのカスタムフィールドの Key と許容データを追跡するための Field Reference JSON ブロックを作成する(Jira Issue エンドポイント)
5. Jira 側からカスタムフィールドを作成できるように、この JSON ブロックを関連する DefectDojo の製品に保存する(DefectDojo UI)
6. 作業内容をテストし、必要なデータがすべて Jira から正しく流れてくることを確認する

#### ステップ1: Jira でカスタムフィールドの名前を記録する

Jira は、Date Picker、Custom Labels、Radio Buttons など、さまざまなコンテキストフィールドをサポートしています。これらのコンテキストフィールドにはそれぞれ異なる Key 値があり、Jira API で確認できます。

次のステップで Jira API から検索する必要があるため、必要なカスタムフィールドの名前をすべて書き出しておいてください。

**カスタムフィールドリストの例(実際のカスタムフィールド名は異なります):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### ステップ2: Jira のカスタムフィールドの Key 値を確認する

この作業は、Jira インスタンス全体の Field Spec URL に移動することから始めます。

Field Spec URL の例を次に示します。

`https://yourcompany-example.atlassian.net/rest/api/2/field`

この API は長い JSON 文字列を返すので、コードエディタやブラウザ拡張機能、あるいは <https://jsonformatter.org/> などを使って読みやすい形式に整形してください。

この URL から返される JSON には、Jira のすべてのカスタムフィールドが含まれています。そのほとんどは DefectDojo とは無関係で、値は `"Null"` になっています。この API レスポンス内の各オブジェクトは、Jira の異なるフィールドに対応しています。Jira UI で作成した各カスタムフィールドの名前と一致する `"name"` 属性を持つオブジェクトを探し、その "key" 属性の値をメモする必要があります。

![image](images/Using_Custom_Fields.png)

JSON 出力の中で一致するオブジェクトが見つかったら、"key" の値を確認できます。この例では `customfield_10050` です。

Jira はカスタムフィールドごとに異なる key 値を生成しますが、これらの key 値は一度作成されると変更されません。今後新しいカスタムフィールドを作成した場合、そのフィールドには新しい key 値が割り当てられます。

**カスタムフィールドリストを更新すると次のようになります:**

* "DefectDojo Custom URL Field" = customfield_10050
* "Another example of a Custom Field" = customfield_12345
* ...

#### ステップ3 - Jira の Issue でカスタムフィールドを見つける

ステップ2で記録したカスタムフィールドを含む Issue を Jira で探します。タイトルの Issue キー(「`EXAMPLE-123`」のような形式)をコピーし、次の URL に移動します。

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

これにより、別の JSON 文字列が返されます。

先ほどと同様に、API の出力には `customfield_##` というオブジェクトパラメータが多数含まれており、それらの値は `null` になっています。これらは Jira がデフォルトで追加するカスタムフィールドで、この Issue には関係ありません。また、前のステップで確認したカスタムフィールドの Key 値と一致する `customfield_##` の値も含まれています。Field Spec の出力とは異なり、これらのカスタムフィールドを識別する名前は表示されないため、ステップ2で Key 値を記録しておく必要があったのです。

![image](images/Using_Custom_Fields_2.png)

**例:**
ステップ2で記録した内容から、`customfield_10050` が DefectDojo Custom URL Field を表すことがわかっています。`EXAMPLE-123` の Issue では、`customfield_10050` の値が `"https://google.com"` であることが確認できます。

#### ステップ4 - 各 Jira カスタムフィールドの Key から JSON Field Reference を作成する

次に、リストにある各カスタムフィールドの値を取得し、それらを(参照用として使う)JSON オブジェクトに格納します。リストに対応しないカスタムフィールドは無視して構いません。

この JSON オブジェクトには、新しい Jira Issue のデフォルト値がすべて含まれます。チームが「変更が必要なデフォルト値」だとひと目でわかるような名前を使うことをお勧めします。例えば「`change-me.com`」や「`Change this paragraph.`」などです。

**例:**

ステップ3から、Jira は「`customfield_10050`」に URL 文字列を期待していることがわかりました。これを使って、サンプルの JSON オブジェクトを作成します。

また、DefectDojo に関連する短いテキストフィールドとして「`customfield_67890`」を見つけたとします。この場合、2番目の API 出力でこのフィールドを確認し、関連付けられた値を調べ、その値もサンプルの JSON オブジェクトに反映します。
​
カスタムフィールドを追加していくと、JSON オブジェクトは次第にこのような形になっていきます。

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

Jira にある DefectDojo 関連のカスタムフィールドすべてが JSON Field Reference に追加されるまで、この作業を繰り返します。

#### データ型と Jira の構文

Date フィールドなど、一部のフィールドは Jira 内で複数のカスタムフィールドに関連していることがあります。その場合は、両方のフィールドを JSON Field Reference に追加する必要があります。

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Label フィールドなど、一部のフィールドは文字列のリストとして扱われる場合があります。JSON Field Reference が Jira の API 出力と一致する形式になっていることを確認してください。

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

他のカスタムフィールドには、Field Reference から除去すべき追加のコンテキスト情報が含まれる場合があります。例えば、Custom Multichoice フィールドには API 出力内に余分なブロックが含まれており、これはフィールドの現在の値を保持しているため、削除する必要があります。

* このフィールドから余分なオブジェクトを削除する必要があります。

```
"customfield_10047": [
    {
      "value": "A"
    },
    {
      "self": "example.url...",
      "value": "C",
      "id": "example ID"
    }
]
```
* 代わりに、以下のように短縮し、2番目の部分は無視して構いません。

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### 完成した Field Reference の例

以下は、各カスタムフィールドが何に対応するかを説明するインラインコメント付きの、完全な JSON Field Reference です。これはあらゆるパターンを網羅した例として示しています。実際の JSON には、Issue 作成時に使用したいカスタム値に応じて、異なる key 値やデータが含まれることになります。

```
{
  "customfield_10050": "https://change-me.com",

  "customfield_10049": "This is a short text custom field",

// two different fields, but both correspond to the same custom date attribute
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",

// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],

// custom number field
  "customfield_10043": 0,

// custom paragraph field
  "customfield_10044": "This is a very long winded way to say CHANGE ME PLEASE",

// custom radio button field
  "customfield_10045": {
    "value": "radio button option"
  },

// custom multichoice field
  "customfield_10047": [
    {
      "value": "A"
    }
  ],

// custom checkbox field
  "customfield_10039": [
    {
      "value": "A"
    }
  ],

// custom select list (singlechoice) field
  "customfield_10048": {
    "value": "1"
  }
}
```

#### ステップ5 - カスタムフィールドを DefectDojo の製品に追加する

これで、これらのカスタムフィールドを、関連する DefectDojo の製品のカスタムフィールドセクションに追加できます。手順は次の通りです。

* 製品の編集画面に移動します - defectdojo.com/product/ID/edit 。
* カスタムフィールドに移動し、JSON Field Reference をプレーンテキストとしてカスタムフィールドのボックスに貼り付けます。
* 「Submit」をクリックします。

#### ステップ6 - 新しい検出事項から Jira のカスタムフィールドをテストする:

これで、Jira に関連付けられた製品で新しい検出事項を作成すると、Jira は含まれる JSON ブロックに従って、これらのカスタムフィールドをすべて自動的に作成します。これらのカスタムフィールドは、デフォルト値(「change-me-please」など)で作成されます。

DefectDojo の製品内で、検出事項 > 新規検出事項の追加 ページに移動します。Jira へのプッシュを確実にするため、検出事項が **アクティブ** かつ **検証済み** であることを確認し、その後 Jira 側でカスタムフィールドが不整合なく正しく作成されていることを確認してください。
