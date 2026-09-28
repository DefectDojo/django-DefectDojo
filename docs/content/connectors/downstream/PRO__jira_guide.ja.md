---
title: Jira(レガシー)
description: Jira 連携を利用する
weight: 1
audience: pro
aliases:
- /ja/issue_tracking/jira/pro__jira_guide/
- /ja/en/share_your_findings/jira_guide
---

> **このページはレガシーな Jira 連携について説明しています。** ここで説明している製品単位の Jira 連携は、**[Jira ダウンストリームコネクタ](/connectors/downstream/about/)** に置き換えられました。このコネクタはすべての DefectDojo Pro インスタンスで一般提供されており、検出事項を Jira にプッシュする際の推奨方法です。Pro のサイドバーでは、この理由から **Connect > Jira** に `LEGACY` バッジが表示されます — 詳細は [メニューバッジ](/navigation/pro__menu_badges/) を参照してください。
>
> **Jira を初めて設定する場合は、このガイドではなく [ダウンストリームコネクタ](/connectors/downstream/about/) から始めてください。**
>
> **すでにレガシー連携を使用していますか?** DefectDojo Pro には、既存のクラシック Jira 設定を、すでにプッシュ済みのチケットも含めてダウンストリームコネクタに移行する組み込みの移行機能があります — 詳細は後述の [Jira ダウンストリームコネクタへの移行](#migrating-to-the-jira-downstream-connector) を参照してください。
>
> レガシー連携は引き続き動作し、このガイドはレガシー連携について正確な内容のままです。

DefectDojo の Jira 連携を使用すると、検出事項のデータを1つ以上の Jira スペースにプッシュできます。これにより、DefectDojo を標準的な開発ワークフローに組み込むことができます。以下はその活用例です。

* AppSec チームは、開発者が使用する Jira スペースへ検出事項を選択的にプッシュできるため、通常の開発作業と並行してイシューの修正を適切に優先順位付けできます。このボードを使う開発者は DefectDojo にアクセスする必要がなく、すべての作業を1か所にまとめておけます。
* DefectDojo は、AppSec チームが使用する双方向の Jira スペースにすべての検出事項をプッシュできるため、イシューの検証作業を分担できます。このボードは DefectDojo と同期を保ち、複雑な修正ワークフローにも対応できます。
* DefectDojo は、個別の製品やエンゲージメントから検出事項を選択的に、それぞれ別の Jira スペースにプッシュできるため、内容を適切なコンテキストに保つことができます。

## Jira ダウンストリームコネクタへの移行

DefectDojo Pro は、既存のクラシック Jira 設定を手作業で再構築する代わりに、ダウンストリームコネクタの設定へ変換できます。

**操作場所:** **Connect \> Downstream** に移動して **Downstream Connectors** ページを開き、**Classic Jira Migration** カードを使用します。**Migrate from classic Jira** をクリックし、確認してください。

このカードは、移行対象のクラシック Jira 設定がある場合、または報告すべき過去の実行結果がある場合にのみ表示されます。そのため、クラシック Jira を一度も使用したことのないインスタンスには表示されません。すべての移行が完了した後もカード自体は残りますが、それ以上行うことがないためボタンは無効化されます。

移行の実行には**グローバルの Maintainer レベルの権限**(具体的には連携編集の権限)が必要であり、ログイン済みのブラウザセッションから実行する必要があります。API トークンで実行することはできません。

### すでにプッシュ済みのチケットはどうなるか

**既存の Jira チケットはそのまま保持され、再度リンクされます。孤立することはなく、コネクタが重複してチケットを開くこともありません。** クラシック Jira によってすでにプッシュされていた検出事項はそれぞれチケットを保持したままとなり、以後はコネクタが同じチケットをその場で更新するようになります。検出事項グループのリンクについても同様に引き継がれます。

唯一の例外は**エンゲージメントのエピック**です。ダウンストリームコネクタにはエピックという概念がないため、エピックのイシューは移行の警告として報告されるのみで、変更されずそのまま残ります。

### 移行される内容

* Jira の**インスタンス**接続(URL と認証情報)は、名前を保ったままダウンストリームコネクタの連携インスタンスになります。
* **深刻度のマッピング**と**ステータスのマッピング**(オープン・クローズの遷移キー)は引き継がれます。
* 各 **Jira プロジェクト**の設定は、プロジェクトキーとイシュータイプを保ったままイシュートラッカーのマッピングになり、同じ製品またはエンゲージメントに割り当てられたままになります。
* **Push All Issues** の設定は維持されます。有効になっていたプロジェクトは、引き続き自動的にプッシュされます。
* **カスタムフィールド**、**クローズ/再オープン遷移フィールド**、**コンポーネント**、**デフォルトの担当者**、**ラベル**はフィールドマッピングに変換されます。*Add Vulnerability Id as a Jira label* を使用していた場合、これもラベルマッピングになります。
* **カスタムイシューテンプレート**のディレクトリはチケットテンプレートになります。標準テンプレートはコピーされません。コネクタにはすでに同等のテンプレートが同梱されているためです。

### 引き継がれない内容

これらは移行実行時の警告として報告されますが、移行を止めることはありません。結果の中にある*「コネクタが引き継げないもの」*のリストを確認してください。

* **Jira → DefectDojo の逆方向同期。** これが最も重要な点です。ダウンストリームコネクタは Jira からの変更を*逆方向に*同期しないため、Jira の解決状況からリスク受容済みや誤検知を適用する解決マッピングは移行されません。**逆方向同期に依存している場合は、クラシック Jira インスタンスの設定をそのまま残してください。** 移行によって削除されることはありません。
* **エンゲージメントのエピックマッピング** — コネクタにはエピックという概念がありません。
* **メモのプッシュ**、**SLA 通知コメント**、**リスク受容期限切れコメント** — これらはコネクタから Jira には投稿されません。
* `summary`、`description`、`project`、`issuetype`、`status` という名前のカスタムフィールド — これらはコネクタによって予約されているため、これらを使用するフィールドマッピングはスキップされます。
* 512文字を超えるカスタムフィールドの値 — 切り詰められるのではなくスキップされます。
* 製品にもエンゲージメントにも紐づいていない Jira プロジェクトは、割り当てが作成されません。

### 移行後にクラシック連携はどうなるか

**二重にプッシュされることはありません。** 移行対象となった各プロジェクトについて、移行処理はクラシック Jira プロジェクトを無効化するため、それ以降はコネクタのみがプッシュを行います。手動で何かを無効化する必要はありません。

クラシックの設定は**削除されず、そのまま保持されます** — インスタンス、プロジェクト、イシューの記録はすべて残り、プッシュ設定のみが無効化されます。これは意図的な仕様です。これにより変更を元に戻せるようになっており、また逆方向同期に依存している場合でもそれが機能し続けます。

**ロールバックするには**、クラシック Jira プロジェクトの設定を再度有効化し、移行によって作成されたコネクタの設定を削除してください。ワンクリックで元に戻す機能はありません。

**再実行しても安全です。** 移行処理はすでに変換した内容を記録しており、2回目の実行時にはそれをスキップするため、重複が発生することはありません。あるプロジェクトやインスタンスで失敗しても、残りは移行が続行されます。失敗したプロジェクトは無効化されずクラシック連携のまま動作し続けるため、調査している間も引き続き機能します。

### 実行中の挙動

移行はバックグラウンドで実行され、進行状況が随時報告されます。完了すると、作成されたコネクタ、マッピング、割り当て、テンプレート、チケットリンクの数、無効化されたクラシックプロジェクトの数、スキップされた内容などのサマリーが、前述の警告とともに表示されます。移行は同時に1つしか実行できません。

# Jira の設定

Jira の設定には、次の手順が必要です。
1. System Settings で Jira 連携を有効化します。有効化するまでは、他の Jira 設定は DefectDojo 全体で非表示になります。
2. ユーザー名/パスワードまたは API トークンを使用して Jira インスタンスを接続します。複数のインスタンスを連携できます。
3. その Jira インスタンスを、DefectDojo 内の1つ以上の製品またはエンゲージメントに追加します。
4. 双方向同期を利用したい場合は、DefectDojo に更新を送信する Jira Webhook を作成します。

## ステップ1: System Settings で Jira 連携を有効化する

Jira 連携はデフォルトで無効になっており、無効な間は他のすべての Jira 関連のコントロールが DefectDojo のインターフェース上で非表示になります。これが最初に設定すべき項目であり、これを有効化するまで以下の手順はいずれも利用できません。

連携が無効な間は、サイドバーに **Jira Instances** の項目が表示されないため、Jira インスタンスを追加する場所がありません。

![image](images/jira-menu-hidden-pro.png)

### 連携を有効化する

1. DefectDojo のサイドバーから **Settings \> System \> System Settings** に移動します。以前のメニューレイアウトを使用しているインスタンスでは、この項目はライセンスパッケージ名にちなんだグループ(**Pro Settings** または **Enterprise Settings**)の下にあります。詳細は [設定メニュー](/navigation/pro__settings_menu/) を参照してください。
​
2. **Jira Integration Settings** セクションで **Enable Jira Integration** にチェックを入れます。
​
3. **Submit** をクリックします。ページを再読み込みしなくても、**Jira Instances** がサイドバーにすぐに表示されます。

![image](images/jira-enable-system-settings-pro.png)

### この設定が制御する内容

**Enable Jira Integration** を有効にすることで、その他の Jira 関連のインターフェースが表示されるようになります。これをオンにすると、次のものが利用可能になります。

* Jira インスタンスの追加・編集を行う **Jira Instances** メニュー
* アセットの ⚙️ メニューにある **Jira Project Settings** ページ、およびエンゲージメントの Jira 設定
* 検出事項および検出事項グループの **Push to Jira** アクション、検出事項フォームおよび一括編集フォームの Jira 関連フィールド、アセット・エンゲージメント・検出事項・検出事項グループの一覧(CSV エクスポートを含む)にある Jira 列

この設定は UI の外でも連携全体を制御します。オフの間は、DefectDojo は(API 経由で送信される `push_to_jira` リクエストを含め)検出事項を Jira にプッシュせず、受信した Jira の Webhook も無視されます。

**Jira Integration Settings** 内の残りの Jira 関連フィールド(**Add Vulnerability ID as Jira Label**、**Enable Jira Web Hook**、**Disable Jira Web Hook Secret**、**Jira Web Hook Secret**、**Jira Minimum Severity**)は、連携がオンかオフかにかかわらず表示されますが、連携が有効になるまでは効果がありません。

## ステップ2: Jira インスタンスを接続する

連携を有効化したら、次のステップは DefectDojo の Jira 連携における Jira インスタンスの接続です。なお、Jira Service Management は現在サポートされていません。

#### Jira から必要な情報

Atlassian では、Jira Cloud と Jira Data Center とで認証方法が異なります。

**Jira Cloud** の場合、次のものが必要です。
* Jira の URL(例: https://yourcompany.atlassian.net/)
* Jira インスタンスでイシューの作成・更新権限を持つアカウント。以下のいずれかが使用できます。
    * 標準の**ユーザー名/パスワード**の組み合わせ
    * **ユーザー名/API トークン**の組み合わせ

**Jira Data Center(または Server)** の場合、次のものが必要です。
* Jira の URL(例: https://jira.yourcompany.com)
* Jira インスタンスでイシューの作成・更新権限を持つアカウント。以下のいずれかが使用できます。
    * 標準の**ユーザー名/パスワード**の組み合わせ
    * **メールアドレス/パーソナルアクセストークン**の組み合わせ

任意で、次のマッピングを設定できます。
* 検出事項の再オープンとクローズをトリガーする Jira の遷移(Transitions)
* 検出事項にリスク受容済みや誤検知のステータスを適用できる Jira の解決状況(Resolutions)(任意)

DefectDojo が使用する Jira アカウント/トークンが対象の Jira スペースでイシューを作成する権限を持っている限り、1つの Jira インスタンス接続で複数の Jira スペースを扱うことができます。

### Jira インスタンスを追加する

1. [ステップ1](#step-1-enable-the-jira-integration-in-system-settings)で説明したとおり、System Settings で **Enable Jira Integration** にチェックが入っていることを確認します。有効にするまで、サイドバーに **Jira Instances** メニューは表示されません。

2. DefectDojo のサイドバーから **Enterprise Settings \> Jira Instances \> + New Jira Instance** ページに移動します。

![image](images/jira-instance-beta.png)

3. この Jira インスタンスが DefectDojo 内で使用する **Configuration Name** を選択します。この名前は DefectDojo 内でのインスタンス接続を示すラベルにすぎず、Jira 側のデータと関連づける必要はありません。

4. 自社の Jira インスタンスの URL を入力します。Jira Cloud を使用している場合、`https://**yourcompany**.atlassian.net` のような形式になります。

5. Jira 用の Username / Password フィールドに、適切な認証方法を入力します。
    * 標準の**ユーザー名/パスワードによる Jira 認証**の場合、これらのフィールドに Jira のユーザー名と対応するパスワードを入力します。
    * **ユーザーの API トークン(Jira Cloud)**による認証の場合、ユーザー名を入力し、パスワードフィールドには対応する **API トークン**を入力します。
    * Jira の**パーソナルアクセストークン(PAT。Jira Data Center および Jira Server でのみ使用)**による認証の場合、パスワードフィールドに PAT を入力します。Jira PAT による認証ではユーザー名は使用されませんが、このフォームでは依然として必須項目のため、PAT を識別するためのプレースホルダー値を入力しておくことができます。

この接続に紐づくユーザーは、Jira インスタンス内でイシューを作成しデータにアクセスする権限を持っている必要があります。

6. Epic Name ID、Re-open Transition ID、Close Transition ID の値を入力する必要があります。これらの値は後から変更できます。Jira にログインした状態で、以下の URL からこれらの値を確認できます。
- **Epic Name ID**: `https://<YOUR JIRA URL>/rest/api/2/field` にアクセスし、Epic Name を検索します。`number` の中にある番号をコピーしてここに貼り付けます。(Team-Managed Space を使用しているなどの理由で)スペースに Epic Name ID が関連付けられていない場合は、このフィールドに 0 を入力します。
- **Re-open Transition ID**: `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` にアクセスし、Jira インスタンスの ID を確認します。Reopen Transition ID フィールドに貼り付けます。
- **Close Transition ID**: `https://<YOUR JIRA URL>/rest/api/latest/issue/<ANY VALID ISSUE KEY>/transitions?expand-transitions.fields` にアクセスし、Jira インスタンスの ID を確認します。Close Transition ID フィールドに貼り付けます。

7. Jira でイシューを作成する際の Default issue type を選択します。選択肢には、標準の Jira イシュータイプである **Bug、Task、Story、Epic** に加えて、カスタムイシュータイプの **Spike** と **Security** があります。これら以外のイシュータイプを使用したい場合は、[support@defectdojo.com](mailto:support@defectdojo.com) までお問い合わせください。

8. Jira でイシューが作成される際のイシューの説明を決定する Issue Template を選択します。

種類は次の2つです。
- **Jira_full**: すべての検出事項情報を Jira のイシューに含めます
- **Jira_limited**: より少ない検出事項情報とメタデータのみを含めます

このフィールドを空欄のままにした場合、デフォルトで **Jira_full** になります。別の種類のテンプレートが必要な場合は、[support@defectdojo.com](mailto:support@defectdojo.com) までご連絡ください。

9. 必要に応じて、イシュー上でトリガーされたときに検出事項のステータスをリスク受容済みまたは誤検知に変更する Jira の Resolution の名前を入力します。

ここでフォームを送信できます。必要であれば、Optional Fields でさらに Jira 連携をカスタマイズすることもできます。このボタンをクリックすると、Jira のイシューに汎用テキストを適用したり、Jira の深刻度マッピングを変更したりできます。

## ステップ3: 製品またはエンゲージメントを Jira に接続する

DefectDojo の各製品・エンゲージメントには、検出事項が Jira のイシューにどのように変換されるかを制御する独自の設定があります。ここから、関連付ける Jira スペースを決定したり、イシュー・エピック・ラベルなどの Jira メタデータを作成する際のデフォルトの動作を設定したりできます。

### 製品に Jira を追加する

このページは、製品の ⚙️(歯車)メニューをクリックし、**Jira Project Settings** ページを開くことで表示できます。

![image](images/jira-project-settings.png)

#### Jira Instance

組織内の別々の製品やチーム用に複数の Jira インスタンスを設定している場合、DefectDojo がどの Jira スペースにイシューを作成するかを指定できます。ドロップダウンメニューからスペースを選択してください。

このメニューに Jira インスタンスが1つも表示されない場合は、DefectDojo のグローバルな Jira 設定(yourcompany.defectdojo.com/jira)でそれらのスペースが接続されていることを確認してください。

#### Project key

これは、DefectDojo で使用したいスペースのキーです。特定のスペースのスペースキーは URL から確認できます。(これは以前は **Jira Project Key** と呼ばれていましたが、2025年9月以降、Jira では **Space Key** と呼ばれるようになりました。)

![image](images/Add_a_Connected_Jira_Project_to_a_Product_3.png)

#### Epic Issue Type Name

Jira での Epic イシュータイプの名前です。デフォルトは "Epic" ですが、Jira インスタンスで別の名前を使用している場合は変更できます。

#### Issue template

ここでは、Jira に送信する DefectDojo のメタデータの量を決定できます。次の2つのオプションから選択します。

* **jira_full**: DefectDojo のすべてのパラメータ(完全な説明、CVE、深刻度など)がイシューに反映されます。Jira 上で検出事項の完全なコンテキストが必要な場合(例えば、DefectDojo にアクセスできない担当者がこのイシューに対応する場合)に有用です。

以下は **jira_full** イシューの例です。
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_4.png)

* **Jira_limited:** イシューには DefectDojo へのリンク、製品/エンゲージメント/テストへのリンク、Reporter と Environment のフィールドのみが反映されます。それ以外のフィールドは DefectDojo 側でのみ管理されます。Jira 上で検出事項の完全なコンテキストが不要な場合(例えば、主に DefectDojo 上で作業する担当者がこのイシューに対応しており、Jira 側にも全体像が必要ない場合)に有用です。

​以下は **jira_limited** イシューの例です。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_5.png)

#### Component

Jira スペースを Components で管理している場合、ここで DefectDojo 用の適切な Component を割り当てることができます。複数の Component を割り当てるには、カンマ区切りのリスト(例: `Security, DevSecOps`)を入力します。各値は個別の component として Jira に送信されます。

#### Custom fields

DefectDojo のイシューで Custom Fields を使用する必要がない場合、このフィールドは 'null' のままにしておくことができます。

ただし、Jira のスペース設定で新規イシューに Custom Fields の使用が**必須**とされている場合は、これらのマッピングをハードコードする必要があります。

DefectDojo はイシュー固有のメタデータを Custom Fields として送信することはできず、送信できるのはデフォルト値のみである点に注意してください。このセクションは、Jira スペース内のすべてのイシューに**これらの Custom Fields が存在することが必須**とされている場合にのみ設定してください。

Custom Fields の設定を始めるには、**[こちらのガイド](#custom-fields-in-jira)**を参照してください。

#### Close / Reopen Transition fields

Jira のワークフローの中には、遷移の一部として特定のフィールドの設定を**必須**とするものがあります。例えば、クローズ画面で Resolution と Justification フィールドが入力されない限りイシューのクローズを拒否するワークフローなどです。上記の Custom fields 設定はイシューの*作成時*にのみ適用されるため、こうしたワークフローの要件を満たすことはできません。

これらの設定がない場合、DefectDojo はフィールドなしでクローズ/再オープンの遷移を送信します。フィールドを必須とするワークフローはその遷移を拒否するため、検出事項と Jira のイシューが同期しなくなります。DefectDojo 側では検出事項が緩和済みと表示される一方、Jira 側ではイシューがオープンのままになります。

**Close Transition fields** および **Reopen Transition fields** の設定には、クローズ/再オープンの遷移呼び出しの `fields` ペイロードとして送信される JSON オブジェクトを指定できます。例えば、*Won't Fix* という Resolution と justification の値を指定してイシューをクローズする場合は、次のようになります。

```json
{
    "resolution": {"name": "Won't Fix"},
    "customfield_10200": "Risk accepted by security team #report-false-positive"
}
```

Jira のワークフローで遷移時のフィールドが不要な場合は、これらの設定を 'null' のままにしておいてください。

**どのフィールドが必要か**

* Jira の管理者に、クローズ/再オープンの**遷移画面**にどのフィールドがあり、そのうちどれがバリデータによって強制されているかを確認してください。設定する JSON は、必須フィールドの**すべて**を満たしている必要があります。必須フィールドが1つでもペイロードに欠けていると、Jira は遷移全体を拒否し、何も設定されません。必須フィールドの一部だけを指定しても意味がありません。
* 逆に、フィールドを送信するにはそのフィールドが**遷移画面上に存在している**必要があります。Jira は、その遷移の画面にないフィールドを設定しようとする遷移を拒否します。
* Jira Cloud の現行のワークフローエディタで構築されたワークフローでは、イシューが完了系のステータスに移行する際、サイトのデフォルトの Resolution が自動的に設定されます。そのため、Resolution が必須であるというだけでは、そこでの単純な遷移がブロックされることはなく、このペイロードで `"resolution"` を指定する実際上の目的は、サイトのデフォルト値の代わりに*意味のある*値(例えば *False Positive*)を選択することにあります。クラシックエディタや Marketplace のバリデータアプリで構築されたワークフローでは、依然として Resolution が厳格に必須とされる場合があります。
* 再オープンの遷移では、通常ワークフロー自体が Resolution をクリアするため、**Reopen Transition fields** には通常、ワークフローが必要とするカスタムフィールドのみを指定すれば十分です。

**注記:**

* 同じ JSON が、その製品またはエンゲージメントの*すべての*クローズ(または再オープン)の遷移で送信されます。値は固定であり、検出事項ごとに変わることはありません。処理内容ごとに異なるフィールドが必要な場合(例えば、誤検知の検出事項と修正済みの検出事項とで異なる Resolution を使いたい場合)は、ステータスごとの遷移フィールドマッピングに対応した DefectDojo Pro Jira Integrator を使用してください。
* 値の形式は Jira の REST API と同じです。テキストフィールドには文字列、resolution には `{"name": ...}`、複数選択フィールドには `[{"name": ...}]` などを使用します。
* これらの設定が未設定または不完全な状態で遷移が拒否されていた場合、設定を修正すればずれは解消されます。次回その検出事項のステータスがプッシュされる際に、設定済みのフィールドで遷移が再試行されます。
* どちらの設定も `/api/v2/jira_projects/` REST エンドポイント(`close_transition_fields` / `reopen_transition_fields`)から利用できるため、API 経由でも管理できます。
* これらのフィールドは、検出事項が**削除された**ことにより DefectDojo がイシューをクローズする場合にも適用されます。値は、クローズがキューに入れられた時点で取得されます。

#### Jira labels

イシューが Jira に作成される際に付与したい該当のラベルを選択します(例: **DefectDojo**、**YourProductName** など)。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_6.png)

#### Default assignee

Jira でのデフォルトの担当者名です。空欄のままにした場合、DefectDojo はイシュー作成時に Jira スペースのデフォルトの動作に従います。

### Jira Project Settings

#### Enabled

このトグルは、DefectDojo がこの製品の検出事項を Jira にプッシュするかどうかを制御します。無効化しても、DefectDojo によって作成された既存の Jira チケットが削除・変更されることはありませんが、それ以降の更新や新規イシューの作成は行われなくなります。

Jira 連携をインスタンスから削除できるのは、関連するイシューが1つも作成されていない場合のみです。イシューがすでに作成されている場合、Jira インスタンスを DefectDojo から完全に削除する方法はありません。

#### Add Vulnerability Id as a Jira label

これを有効にすると、脆弱性 ID のデータを自動的に Jira のラベルとして追加できます。脆弱性 ID は各セキュリティツールから検出事項に追加されるもので、Common Vulnerabilities and Exposures(CVE)ID の場合もあれば、その検出事項を報告したツール固有の別の形式である場合もあります。

#### Push All Issues

チェックすると、DefectDojo はアクティブかつ検証済みの検出事項を自動的に Jira にイシューとしてプッシュします。チェックしない場合、すべての検出事項は(個別または一括プッシュで)手動で Jira にプッシュする必要があります。

この設定が有効な場合、検出事項のステータスが変化しても Jira のイシューは DefectDojo と同期し続けます。

#### Enable Engagement Epic Mapping

DefectDojo では、エンゲージメントは一連の作業のまとまりを表します。各エンゲージメントには1つ以上のテストが含まれ、各テストには緩和が必要な1つ以上の検出事項が含まれます。Jira のエピックも同様の考え方であり、このチェックボックスを使うとエンゲージメントを Jira にエピックとしてプッシュできます。

* DefectDojo 上のエンゲージメント。下部に3件の検出事項がリストされている点に注目してください。
​
![image](images/Add_a_Connected_Jira_Project_to_a_Product_8.png)
* 同じエンゲージメントが Jira にプッシュされるとエピックになる様子。エンゲージメントの検出事項も併せてプッシュされ、エンゲージメント内に子イシューとして存在します。

![image](images/Add_a_Connected_Jira_Project_to_a_Product_9.png)

#### Push Notes

有効にすると、Jira のコメントが該当する DefectDojo の検出事項の Notes に反映されます。逆に、検出事項のメモは該当する Jira のイシューにコメントとして追加されます。

#### Send SLA Notifications As Comments

有効にすると、DefectDojo の Service Level Agreement のルールに違反したイシューには、その旨を示すコメントが Jira のイシューに追加されます。これらのコメントは、イシューが解決するまで毎日投稿されます。

Service Level Agreement は、DefectDojo の **Configuration \> SLA Configuration** で設定し、各製品に割り当てることができます。

#### Send Risk Acceptance Expiration Notifications As Comment

有効にすると、関連する DefectDojo のリスク受容が期限切れになったイシューには、その旨を示すコメントが Jira のイシューに追加されます。これらのコメントは、イシューが解決するまで毎日投稿されます。

### Engagement-Level Jira Settings

デフォルトでは、エンゲージメントは**製品から Jira 設定を継承**します。ただし、個々のエンゲージメントごとに Jira 設定を上書きすることもできます。

エンゲージメントレベルの Jira 設定にアクセスするには、エンゲージメントの ⚙️(歯車)メニューをクリックし、**Jira Project Settings** ページを開きます。

ここから **Inherit from Product** のチェックを外し、**Project Key**、**Issue Template、Custom Fields、Jira Labels、Default Assignee** などの設定にエンゲージメント固有の値を指定できます。

エンゲージメントに独自の Jira プロジェクトが割り当てられると、それ以降は製品から設定を継承できなくなる点に注意してください。

![image](images/Creating_Issues_in_Jira_5.png)

## Step 4: Configure Bidirectional Sync: Jira Webhook

Jira連携ではWebhookによる双方向同期が可能です。DefectDojoは一意のアドレスでJiraの通知を受信し、設定内容に応じて、検出事項にJiraのコメントを反映したり、Jira経由で検出事項を解決したりできます。

### Locating your Jira Webhook URL

Jira Webhookは、サイドバーの **Enterprise Settings > System Settings** にあるシステム設定フォームの **Jira Integration Settings** に記載されています。

DefectDojoが受信したJiraの通知を処理できるようにするには、同じページで **Enable Jira Web Hook** にもチェックを入れる必要があります。このチェックボックス、または **Enable Jira Integration**([Step 1](#step-1-enable-the-jira-integration-in-system-settings)を参照)のいずれかがオフになっている場合、受信したWebhookは無視されます。

![image](images/Configuring_the_Jira_DefectDojo_Webhook.png)

### Creating the Jira Webhook

1. `**https:// \<YOUR JIRA URL\> /plugins/servlet/webhooks**` にアクセスします。
2. 「Create a Webhook」をクリックします。
3. 「URL」というラベルの付いたフィールドに次を入力します: `https:// \<**YOUR DOJO DOMAIN**\> /jira/webhook/ \<**YOUR GENERATED WEBHOOK SECRET**\>`。Web Hook Secretは、上記のJira Integration Settingsに記載されています。
4. 「Comments」の下で「Created」を有効にします。「Issue」の下で「Updated」を有効にします。
5. JiraインスタンスがDefectDojoインスタンスの使用するSSL証明書を信頼していることを確認してください。JIRA CloudでDefectDojoを使用する場合、[グローバルに信頼された認証局によって署名された有効なSSL/TLS証明書](https://developer.atlassian.com/cloud/jira/platform/deprecation-notice-registering-webhooks-with-non-secure-urls/)を使用する必要があります。

このWebhookを使用するために、Jira側でSecretを作成する必要はありません。SecretはDefectDojoのURLに組み込まれているため、完全なURLをJiraのWebhookフォームに追加するだけで十分です。

受信するWebhookリクエストは、そのURLに含まれるSecretによって認証されます。そのため、完全なURLは認証情報として扱い、非公開に保ってください。

#### Testing the Webhook

DefectDojoの検出事項から1つ以上のIssueを作成したら、そのうちの1つの検出事項にメモを追加することでWebhookをテストできます。設定が正しければ、そのメモはJiraのWebhookによってIssueへのコメントとして受信されるはずです。

これが正しく機能しない場合、Jiraインスタンス側のファイアウォールがWebhookをブロックしていることが原因である可能性があります。

* DefectDojoのFirewall Rulesには **Jira Cloud** 用のチェックボックスがあり、DefectDojoがJiraからのWebhookメッセージを受信できるようにするには、これを有効にする必要があります。

### Alternative: Using Jira Automation (Send web request)

Jiraインスタンスによっては、`/plugins/servlet/webhooks` 以下のシステムWebhookが許可されていない場合があります。たとえば、その管理領域へのアクセスが制限されており、**Jira Automation** のルールのみが許可されている場合です。そのような場合でも、Automationの **Send web request** アクションを使用して、同じDefectDojo Webhookエンドポイントにポストすることで、同じ双方向同期を実現できます。

DefectDojoのWebhookエンドポイントは、`Content-Type: application/json` を指定し、URLパスに有効なSecretを含む任意のHTTP `POST` を受け付けます。リクエストがJiraのシステムWebhook機構から送信されたものである必要は**ありません**。そのため、Automationの「Send web request」アクションはそのまま代替手段として機能します。

#### Prerequisites

システムWebhookと同じ前提条件が適用されます。

* ⚙️ **Configuration > System Settings** ページで、**Enable JIRA integration** と **Enable JIRA web hook** の両方がチェックされていること。
* 同じページで、空でない **Jira webhook secret** が設定されていること。このSecretに使用できる文字は `A-Z`、`a-z`、`0-9`、`_`、`-` のみです。
* 検出事項(またはFinding Group)がすでにJira Issueにリンクされていること。IssueがDefectDojoの検出事項にリンクされていない場合、リクエストは受け付けられます(HTTP `200`)が、何のアクションも行われません。

#### How DefectDojo processes the request

* DefectDojoはトップレベルの `webhookEvent` フィールドによって処理を分岐します。処理されるのは `"jira:issue_updated"` と `"comment_created"` のみで、それ以外の値は受け付けられますが無視されます。Automationはこのフィールドを自動的に追加**しない**ため、リクエストボディに自分で含める必要があります。
* そのため、リクエストの **Body** を **Custom data** に設定し、以下のJSONを指定してください。**Empty** および **Jira issue data** のBodyオプションには必要な `webhookEvent` フィールドが含まれないため、DefectDojoはそれらを無視します。
* このエンドポイントは、更新が適用されたかどうかにかかわらず、常にHTTP `200` を返します。成功したか失敗したかはレスポンスボディとDefectDojoのログでのみ確認できます。Automationの監査ログに表示される `200` は、それ単体で更新が検出事項に反映されたことを保証する**ものではありません**。

#### Rule 1 — Issue updated

以下の内容でAutomationルールを作成します。

* **Trigger:** *Issue transitioned*(または、同期対象のフィールドが変化したときに発火する別のトリガー。例: StatusでのField value changed)。
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

Issue更新に関する制約:

* `issue.id` は、Issueキー(例: `PROJ-123`)ではなく、**数値のJira内部Issue ID**(`{{issue.id}}`)である必要があります。DefectDojoはこの数値IDを使って更新対象の検出事項を照合します。
* `resolution` と `updated` の両フィールドは常に存在している必要があります。`resolution` は `null` でも構いませんが、どちらかのフィールドが欠けている場合、リクエストは受け付けられ(`200`)ますが、何も処理されずに無視されます。
* ステータスの同期と自動緩和は `status.statusCategory.key` によって制御されます。Jira側の値は `new`(To Do)、`indeterminate`(In Progress)、`done`(Done)です。検出事項が緩和済みになるのは、Issueが実際にクローズされた場合のみであり、resolutionの値がたまたま存在するというだけでは緩和されません。

#### Rule 2 — Issue commented

2つ目のAutomationルールを以下の内容で作成します。

* **Trigger:** *Issue commented*
* **Action:** *Send web request* — ルール1と同じURL、メソッド、ヘッダー、*Custom data* のBodyオプションを使用し、Bodyの内容は以下の通りです。

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

* `body` と `updateAuthor` の両方が存在している必要があります。
* DefectDojoは対象のIssueを `comment.self` のURL、具体的には `.../issue/<id>/comment/...` の部分に含まれる `<id>` から特定します。そのため、そこには `{{issue.id}}`(数値ID)を含める必要があります。
* **Loop prevention:** コメントの投稿者がDefectDojo自身のコメント投稿に使用しているJiraアカウントと一致する場合、DefectDojoはエコーループを防ぐためそのコメントをスキップします。すべてのコメントを取り込みたい場合は、DefectDojoのJiraインスタンス設定で使用しているものとは**異なる**Jiraユーザーとして、Automationルールを実行してください。

#### A note on smart values

上記で示したスマート値(`{{issue.id}}`、`{{issue.status.statusCategory.key}}`、`{{comment.author.accountId}}` など)はJira Cloudの標準的な名称ですが、インスタンスによって異なる場合があります。本番運用を開始する前に、Automationのペイロードプレビュー機能を使って、各スマート値が期待通りに解決されることを確認してください。

## Testing the Jira integration

#### Test 1: Do Findings successfully push to Jira?

Jira連携が正しく機能しているかをテストするには、DefectDojo上でJiraに関連付けられた製品に新しい空の検出事項を追加します。**Product > Findings > Add New Finding** から行います。

任意のタイトル、深刻度、説明を入力し、「Finished」をクリックします。その検出事項は、関連するすべてのメタデータとともにJira上でIssueとして表示されるはずです。

Jira Issueが正しく作成されない場合は、Notificationsでエラーコードを確認してください。

* DefectDojoのJira設定に関連付けられたJiraユーザーが、該当するJiraスペースでIssueを作成・更新する権限を持っていることを確認してください。

#### Test 2: Jira Webhooks send to DefectDojo

Jira Webhookをテストするには、JIRA上にもIssueとして存在している検出事項(たとえば上のセクションで作成したテスト用Issue)にメモを追加します。

Webhookが正しく設定されていれば、そのメモはJira上でIssueへのコメントとして表示されるはずです。

これが正しく機能しない場合、Jiraインスタンス側のファイアウォールがWebhookをブロックしていることが原因である可能性があります。

* DefectDojoのFirewall Rulesには **Jira Cloud** 用のチェックボックスがあり、DefectDojoがJiraからのWebhookメッセージを受信できるようにするには、これを有効にする必要があります。

## Disconnecting from Jira

Jira連携は、関連するIssueが1つも作成されていない場合にのみ、インスタンスから削除できます。Issueがすでに作成されている場合、DefectDojoからJiraインスタンスを完全に削除する方法はありません。

ただし、製品レベルで無効化することでJira連携を停止することはできます。(製品の ⚙️ Gearメニューからアクセスできる)**Jira Project Settings** ページで、**Enabled** トグルのチェックを外してください。これにより、DefectDojoが作成した既存のJiraチケットが削除・変更されることはありませんが、それ以降の更新は無効になります。

# Pushing Findings To Jira

JIRAマッピングが設定された製品では、いくつかの方法で検出事項をJiraへIssueとしてプッシュできます。検出事項は、個別に、一括で、Finding Groupとして、または自動でプッシュすることが可能です。

## Push a Single Finding

1. プッシュしたい検出事項を開きます。
2. **☰ Finding Menu** をクリックし、**Push to Jira** を選択します。
3. 確認を求められたらプッシュを確定します。DefectDojoはJira Issueを作成し、その検出事項にリンクします。

Issueが作成されると、DefectDojoは検出事項ページにJira Issueへのリンクを表示します。

![image](images/Creating_Issues_in_Jira_2.png)

**Edit Finding** フォームで検出事項を編集する際に、**Push to Jira** チェックボックスをオンにすることもできます。検出事項が保存されると、Jiraへプッシュされます。

### Updating a Linked Jira Issue

検出事項にすでにリンクされたJira Issueがある場合、再度 **Push to Jira** を選択すると、DefectDojo上で行われた変更が既存のJira Issueに反映されます。製品で **Push All Issues** が有効になっている場合、この同期は自動的に行われます。

### Unlinking a Finding from Jira

検出事項とJira Issueの関連付けを解除するには、**☰ Finding Menu** をクリックして **Unlink From Jira** を選択します。これによりDefectDojo側のリンクは削除されますが、Jira Issue自体は削除されません。

## Bulk Push Findings

Bulk Updateフォームを使用すると、複数の検出事項を一度にJiraへプッシュできます。

1. 検出事項の一覧で、プッシュしたい検出事項をチェックボックスで選択します。
2. **Bulk Update** フォームを開きます。
3. **Jira Settings** の下にある **Push to Jira** チェックボックスをオンにします。
4. **Submit** をクリックします。

選択した検出事項は、Jiraへのプッシュ待ちとしてキューに登録されます。DefectDojoは、何件の検出事項がキューに登録されたかを示す確認メッセージを表示します。

## Push Engagements as Epics

Jira Project Settingsで **Enable Engagement Epic Mapping** がオンになっている場合、エンゲージメントをEpicとしてJiraへプッシュできます。そのエンゲージメントの検出事項は、そのEpic内のChild Issueとしてプッシュされます。

エンゲージメントをEpicとしてプッシュする手順:

1. プッシュしたいエンゲージメントを開きます。
2. **☰ Engagement Menu** をクリックし、**Push to Jira** を選択します。
3. 必要に応じて **Epic Name**(空欄の場合はエンゲージメント名がデフォルトで使用されます)と **Epic Priority** を指定します。
4. **Push to Jira (Create Epic)** をチェックし、フォームを送信します。

## Push Finding Groups as Jira Issues

Finding Groupsが有効になっている場合、複数の検出事項からなるグループを、検出事項ごとに個別のIssueとしてではなく、単一のIssueとしてJiraへプッシュできます。

Finding Groupをプッシュする手順:

1. Finding Groupを開きます。
2. **☰ Finding Group Menu** をクリックして **Push to Jira** を選択するか、Finding Groupを編集する際に **Push to Jira** チェックボックスをオンにします。

Finding Groupに関連付けられたJira Issueを削除する必要がある場合は、Jiraインスタンス側から直接削除する必要があります。

### Automatically Create and Push Finding Groups

製品で **Push All Issues** が有効になっており、インポート時に **Group By** オプションが選択されている場合:

Finding Groupsが正常に作成されている限り、個々の検出事項ではなくFinding Groupが自動的にIssueとしてJiraへプッシュされます。

![image](images/Creating_Issues_in_Jira_4.png)

## Automatic Push Behaviour

DefectDojoは、いくつかのシナリオで検出事項とその更新を自動的にJiraへプッシュできます。

### Push All Issues

製品のJira Project Settingsで **Push All Issues** 設定が有効になっている場合、DefectDojoはすべての**アクティブ**かつ**検証済み**の検出事項に対して自動的にJira Issueを作成します。これにはスキャンのインポートによって作成された検出事項も含まれます。Jira Issueが作成されると、検出事項のステータスが変化した後もDefectDojoと同期し続けます。

### Auto-Sync on Status Changes

**Push All Issues**、またはシステムレベルの **Finding Jira Sync** 設定が有効になっている場合、検出事項に対して特定の操作が行われると、DefectDojoはリンクされたJira Issueを自動的に更新します。

* **Request Review** - リンクされたJira Issue(検出事項がグループに属している場合はそのFinding GroupのJira Issue)にコメントが追加されます。
* **Clear Review** - リンクされたJira Issueにコメントが追加されます。
* **Close Finding** - リンクされたJira Issueがクローズを反映するよう更新されます。**Push Notes** が有効な場合は、コメントも追加されます。

## Jira Comments and Notes

Jira Project Settingsで **Push Notes** が有効になっている場合:

* Jira Issueにコメントが追加されると、同じ内容が検出事項の **メモ** セクションに追加されます。
* 同様に、検出事項にメモが追加されると、そのメモはJira Issueにコメントとして追加されます。

## Jira Status Changes

Jira Instanceの設定には、検出事項のステータス変更をトリガーする2つのJira Transitionの項目があります。

* Jira上で **'Close' Transition** が実行されると、関連する検出事項もクローズされ、DefectDojo上で**非アクティブ**かつ**緩和済み**とマークされます。DefectDojoはこの変更を検出事項ページの **Mitigated By** の項目に記録します。
​
![image](images/Creating_Issues_in_Jira_3.png)

* Jira Issueで **'Reopen' Transition** が実行されると、関連する検出事項はDefectDojo上で**アクティブ**に設定され、**緩和済み**のステータスは解除されます。

## Mapping Jira Resolutions to Risk Acceptance / False Positive

Jira Instanceの設定には、Jiraの **Resolution** をDefectDojoの検出事項ステータスにマッピングするための、任意設定の2つのフィールドがあります。

* **Risk Accepted Finding Mapping Resolution** — Jira Issueがこのresolutionでクローズされると、リンクされた検出事項はDefectDojo上で**リスク受容済み**になります。
* **False Positive Finding Mapping Resolution** — Jira Issueがこのresolutionでクローズされると、リンクされた検出事項はDefectDojo上で**誤検知**になります。

### Status vs Resolution: A Common Point of Confusion

これらのフィールドがマッピングするのはJiraの **Resolution** であり、Jiraの **Status** ではありません。StatusとResolutionは、Jiraにおける独立した2つの概念です。StatusはIssueがワークフロー上のどこにあるか(Open、In Progress、Doneなど)を表し、Resolutionはどのように解決されたか(Fixed、Won't Do、Duplicate、False Positiveなど)を表します。

### Prerequisite: A "Set issue resolution" post-function on the Jira workflow transition

Jiraのワークフローエンジンは、Resolutionフィールドを自動的には設定しません。特定のResolutionでIssueをクローズすべき各transitionには、そのtransition自体に **Set issue resolution** ポストファンクションを設定する必要があります。このポストファンクションがないと、Issueは新しいStatusに遷移してもResolutionは空のままとなり、DefectDojo側のマッピングは照合対象を得られません。

Jiraの管理者は、**Project Settings → Workflows → (edit workflow) → (select the closing transition) → Post Functions → Add post function → Set issue resolution** からこのポストファンクションを追加できます。

# Custom Fields in Jira

<span style="background: rgba(243, 122, 78,0.5">DefectDojoは現時点で、Issue固有の情報をこれらのCustom Fieldsに渡すことをサポートしていません。これらのフィールドは、Issue作成後にJira上で手動で更新する必要があります。各Custom Fieldは、DefectDojoからはデフォルト値でのみ作成されます。</span>

<span style="background: rgba(0, 207, 83, 0.44)"> Jira Cloudでは現在、アプリ内で直接デフォルトのCustom Field値を作成できます。設定方法の詳細は[Atlassianのカスタムフィールドに関するドキュメント](https://support.atlassian.com/jira-cloud-administration/docs/configure-a-custom-field/)を参照してください。</span>

DefectDojoに組み込まれているJira Issue Type(**Bug、Task、Story**、**Epic**)は、そのまま使用できるように設定されています。DefectDojoのデータフィールドは、Jiraの対応するフィールドに自動的にマッピングされます。DefectDojoはデフォルトで、新規作成するすべてのIssueにPriority、Labels、Reporterを割り当てます。

Jiraの設定によっては、Issueを作成する前に追加のカスタムフィールドを考慮する必要がある場合があります。この手順に従うことで、DefectDojo -> Jira連携でこれらのカスタムフィールドを扱えるようになり、Issueが確実に作成されるようになります。これらのカスタムフィールドは、DefectDojoからリンクされたJiraインスタンスへ送信されるすべてのAPI呼び出しに追加されます。

Jiraですでにカスタムフィールドを使用していない場合は、この手順に従う必要はありません。

1. Jira内のCustom Fieldsの名前を記録する(**Jira UI**)
2. 新しいCustom FieldsのKey値を特定する(Jira Field Spec Endpoint)
3. Key値を参照として、各Custom Fieldで有効なデータ形式を確認する(Jira Issue Endpoint)
4. すべてのCustom Field Keyと有効なデータを追跡するためのField Reference JSONブロックを作成する(Jira Issue Endpoint)
5. JiraからCustom Fieldsを作成できるように、関連付けられたDefectDojoの製品にJSONブロックを保存する(DefectDojo UI)
6. 作業内容をテストし、必要なデータがすべてJiraから正しく流れていることを確認する

#### Step 1: Record the names of your Custom Fields in Jira

Jiraは、Date Picker、Custom Label、Radio Buttonなど、さまざまなContext Fieldsをサポートしています。これらのContext Fieldsはそれぞれ異なるKey値を持っており、Jira APIから確認できます。

必要なCustom Fieldの名前をそれぞれ書き出しておいてください。次のステップでJira APIから検索する際に必要になります。

**Example of a Custom Field list (your Custom Field names will be different):**

* DefectDojo Custom URL Field
* Another example of a Custom Field
* ...

#### Step 2: Finding your Jira Custom Field Key Values

まず、Jiraインスタンス全体のField Spec URLにアクセスするところから始めます。

Field Spec URLの例を以下に示します。

`https://yourcompany-example.atlassian.net/rest/api/2/field`

このAPIは長いJSON文字列を返すので、読みやすいテキストに整形してください(コードエディタ、ブラウザ拡張機能、または<https://jsonformatter.org/>などを使用します)。

このURLから返されるJSONには、Jiraのすべてのカスタムフィールドが含まれていますが、そのほとんどはDefectDojoには関係がなく、値は `"Null"` になっています。このAPIレスポンス内の各オブジェクトは、Jiraの異なるフィールドに対応しています。Jira UIで作成した各Custom Fieldの名前と一致する `"name"` 属性を持つオブジェクトを探し、その「key」属性の値を記録する必要があります。

![image](images/Using_Custom_Fields.png)

JSON出力の中で一致するオブジェクトを見つけたら、「key」の値を特定できます。この例では `customfield_10050` です。

Jiraは各Custom Fieldに対して異なるkey値を生成しますが、これらのkey値は一度作成されると変わりません。今後新たにCustom Fieldを作成した場合、そのフィールドには新しいkey値が割り当てられます。

**Expanding our Custom Field list:**

* "DefectDojo Custom URL Field" = customfield_10050
* "Another example of a Custom Field" = customfield_12345
* ...

#### Step 3 - Finding the Custom Fields on a Jira Issue

ステップ2で記録したCustom Fieldsを含むIssueをJira内で探します。タイトルのIssueキー(「`EXAMPLE-123`」のような形式)をコピーし、次のURLにアクセスします。

`https://yourcompany-example.atlassian.net/rest/api/2/issue/EXAMPLE-123`

これにより、別のJSON文字列が返されます。

先ほどと同様に、このAPI出力には `null` 値を持つ多数の `customfield_##` オブジェクトパラメータが含まれています。これらはJiraがデフォルトで追加するカスタムフィールドで、このIssueには関係ありません。また、前のステップで確認したCustom Field Key値と一致する `customfield_##` の値も含まれています。Field Spec出力とは異なり、これらのカスタムフィールドを識別する名前は表示されないため、ステップ2でkey値を記録しておく必要があったのです。

![image](images/Using_Custom_Fields_2.png)

**Example:**
ステップ2で記録した通り、`customfield_10050` はDefectDojo Custom URL Fieldを表しています。`EXAMPLE-123` のIssueでは、`customfield_10050` の値が `"https://google.com"` であることが確認できます。

#### Step 4 - Creating a JSON Field Reference from each Jira Custom Field Key

次に、リストにある各Custom Fieldの値を取得し、(参照用として使う)JSONオブジェクトに格納します。リストに対応しないCustom Fieldは無視して構いません。

このJSONオブジェクトには、新規Jira Issueに使用するすべてのデフォルト値が含まれます。チームが「変更が必要なデフォルト値」だとひと目でわかる名前を使うことをお勧めします。例: 「`change-me.com`」「`Change this paragraph.`」など。

**Example:**

ステップ3から、Jiraが「`customfield_10050`」にはURL文字列を期待していることがわかりました。これを使ってJSONオブジェクトの例を作成できます。

「`customfield_67890`」として識別された、DefectDojo関連の短いテキストフィールドも見つかったとします。2回目のAPI出力でこのフィールドを確認し、対応する値を見て、そのままJSONオブジェクトの例にも参照値として記載します。
​
Custom Fieldsを追加していくと、JSONオブジェクトは次のようになります。

```
{
	"customfield_10050": "https://change-me.com",
	"customfield_67890": "This is the short text custom field."
}
```

DefectDojoに関係するJiraのカスタムフィールドがすべてJSON Field Referenceに追加されるまで、この手順を繰り返します。

#### Data types & Jira Syntax

Dateフィールドなど、一部のフィールドはJira内の複数のカスタムフィールドに関連している場合があります。その場合は、両方のフィールドをJSON Field Referenceに追加する必要があります。

```
  "customfield_10040": "1970-01-01",
  "customfield_10041": "1970-01-01T03:30:00.000+0200",
```

Labelフィールドなど、他のフィールドは文字列のリストとして管理される場合があります。JSON Field ReferenceがJiraのAPI出力と一致する形式になっていることを確認してください。

```
// a list of custom labels on a Jira object
  "customfield_10042": [
    "custom-label-one",
    "this-is-default",
    "change-me-please"
  ],
```

他のカスタムフィールドには、Field Referenceから削除すべき追加の文脈情報が含まれる場合があります。たとえば、Custom Multichoice Fieldは、フィールドの現在の値を保持する余分なブロックをAPI出力に含んでいるため、これを削除する必要があります。

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
* 代わりに、以下のように短縮し、2番目の部分は無視できます。

```
"customfield_10047": [
   {
      "value": "A"
   }
]
```

#### Example Completed Field Reference

各カスタムフィールドが何を表すかを説明するインラインコメント付きの、完成したJSON Field Referenceを以下に示します。これはあらゆるケースを網羅する例として示しています。実際のJSONは、Issue作成時に使用したいCustom Valueに応じて、異なるkey値とデータになります。

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

#### Step 5 - Adding the Custom Fields to a DefectDojo Product

これで、(製品の ⚙️ Gearメニューからアクセスできる)Jira Project Settingsページで、これらのカスタムフィールドを関連付けられたDefectDojoの製品に追加できます。JSON Field Referenceをプレーンテキストとして **Custom Fields** ボックスに貼り付けて保存してください。

#### Step 6 - Testing your Jira Custom Fields from a new Finding:

これで、Jiraに関連付けられた製品で新しい検出事項を作成すると、含まれるJSONブロックに従って、これらのCustom FieldsがすべてJira上に自動的に作成されます。これらのCustom Fieldsは、デフォルト値(「change-me-please」など)で作成されます。

DefectDojoの製品内で、Findings > Add New Findingページに移動します。検出事項がJiraへプッシュされるように、**アクティブ**かつ**検証済み**の両方になっていることを確認し、Jira側でCustom Fieldsが不整合なく正常に作成されていることを確認してください。
