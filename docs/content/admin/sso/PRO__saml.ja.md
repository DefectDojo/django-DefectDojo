---
title: SAML の設定
description: DefectDojo Pro で SAML を設定する
weight: 1
audience: pro
---

DefectDojo Pro は **Enterprise Settings** UI 経由での SAML 認証をサポートしています。オープンソース版の DefectDojo には SSO は含まれていません。オープンソース版のアクセス制御については [Authorized Users](/admin/user_management/os__authorized_users/) を参照してください。

## ACS URL (Assertion Consumer Service)

ユーザーが認証された後、SAML レスポンスをどこに POST すればよいかを ID プロバイダーが把握している必要があります。DefectDojo の ACS URL は次のとおりです。

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

このエンドポイントについて知っておくべき点がいくつかあります。

- **このエンドポイントは `POST` リクエストのみを受け付けます。** ACS URL をブラウザで直接開くと GET リクエストが発行され、**HTTP 405 Method Not Allowed** が返されます。これは想定された動作であり、SAML が壊れている、または設定を誤っていることを意味するものではありません。このエンドポイントは、ブラウザに URL を直接入力して呼び出すものではなく、SAML リダイレクトフローの一部として IdP から呼び出されるように設計されています。
- **ACS URL は DefectDojo Cloud インスタンス上で常に利用可能です。** IdP をこの URL に向ける前に、DefectDojo で SAML を有効にしておく必要はありません。IdP 側と DefectDojo 側の設定はどちらを先に行っても構いません。

## Setup

1. **Enterprise Settings > SAML Settings** を開きます。

   ![image](images/sso_betaui_1.png)

2. **Entity ID** を設定します。これは、SAML ID プロバイダーが DefectDojo を識別するために使用するラベルまたは URL です。このフィールドは必須です。

3. 必要に応じて **Login Button Text** を設定します。これは、ユーザーが SAML ログインを開始するためにクリックするボタンに表示されるテキストです。

4. 必要に応じて、ユーザーが DefectDojo からログアウトした後にリダイレクトする **Logout URL** を設定します。

5. **Name ID Format** を選択します。
   - **Persistent** — ユーザーはセッションをまたいで一貫した SAML ID で識別されます。
   - **Transient** — ユーザーはログインのたびに異なる SAML ID を受け取ります。
   - **Entity** — すべてのユーザーが単一の SAML NameID を共有します。
   - **Encrypted** — 各ユーザーの NameID が暗号化されます。

6. **Required Attributes** — DefectDojo が SAML レスポンスから要求する属性を指定します。

7. **Attribute Mapping** — IdP が送信する属性を、それが値を設定すべき DefectDojo のユーザーフィールドにマッピングします。各行は 1 つの **SAML Attribute** と 1 つの **DefectDojo Field** をペアにします。行を追加するには **Add Attribute Mapping** を使用し、削除するにはゴミ箱アイコンを使用します。

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** は自由入力欄で、IdP が実際に発行する属性名と一致させる必要があります。一部の IdP(Entra ID / Azure AD など)は、わかりやすい名前ではなく `http://schemas.microsoft.com/identity/claims/emailaddress` のような完全修飾クレーム URI を送信します。IdP が何を送信しているかわからない場合は、**Enable SAML Debugging** を有効にし([トラブルシューティング](#troubleshooting) を参照)、ログでアサーションを確認してください。
   - **DefectDojo Field** は、**Username**、**First Name**、**Last Name**、**Email** のリストから選択します。
   - 少なくとも **Username** に対応する属性はマッピングしてください。DefectDojo は、SAML ログインを既存のアカウントに照合する際、ユーザー名でユーザーを検索します。
   - **Email** への属性のマッピングを強く推奨します。DefectDojo は通知にメールアドレスを使用するほか、受信したログインをメールアドレスで既存のアカウントに照合する際にも使用します。
   - 同じ属性を複数のフィールドに使用できます。たとえば、メールのクレームを **Email** と **Username** の両方に使用できます。ただし逆は許可されません。各 DefectDojo フィールドにマッピングできる属性は 1 つだけです。
   - 片方のみが入力された行は保存時に拒否され、該当するセルがハイライトされます。追加したものの入力しなかった行は、エラーとして扱われるのではなく破棄されます。

8. **Remote SAML Metadata** — SAML ID プロバイダーのメタデータがホストされている URL です。

9. フォームの下部にある **Enable SAML** をチェックして、SAML ログインを有効にします。DefectDojo のログインページに **Login With SAML** ボタンが表示されます。

   ![image](images/sso_saml_login.png).

## Additional Options

* **Create Unknown User** — SAML レスポンスにユーザーが見つからない場合、新しい DefectDojo ユーザーを自動的に作成します。
* **Allow Unknown Attributes** — Attribute Mapping に記載されていない属性を持つユーザーのログインを許可します。
* **Sign Assertions/Responses** — 受信するすべての SAML レスポンスに署名を必須にします。
* **Sign Logout Requests** — DefectDojo が送信するすべてのログアウトリクエストに署名します。
* **Force Authentication** — 既存のセッションの有無にかかわらず、ログインのたびに ID プロバイダーでの認証をユーザーに要求します。
* **Enable SAML Debugging** — トラブルシューティング用に詳細な SAML 出力をログに記録します。ログ出力がどこに表示されるかについては、[トラブルシューティング → SAML Debugging output](#saml-debugging-output) を参照してください。

## SAML Group Mapping

DefectDojo は SAML アサーションを使用して、ユーザーを [User Groups](../../user_management/create_user_group/) に自動的に割り当てることができます。DefectDojo のグループはすべてのメンバーに権限を付与するため、Group Mapping を使えば権限をまとめて管理できます。これは SAML 経由で権限を設定する唯一の方法です。

**グループマッピングは任意です。** UI 上では **Group Name Attribute** と **Group Limiter Regex Expression** のフィールドに必須項目を示すアスタリスク(`*`)が表示されますが、これらを入力しなくても SAML フォームは送信でき、グループマッピングなしでも SAML ログインは機能します。SAML を有効にする前に、IdP 側(Azure AD のアプリケーションロールなど)でグループやロールを事前に構築しておく必要はありません。DefectDojo にアサーションからグループメンバーシップを読み取らせたい場合にのみ、これらのフィールドを設定してください。グループマッピングを設定しない場合、新しく作成された SSO ユーザーにはデフォルトで権限が付与されません。詳細は下記の [Default access for SSO-provisioned users](#default-access-for-sso-provisioned-users) を参照してください。

**Group Name Attribute** フィールドは、SAML アサーション内のどの属性にユーザーのグループメンバーシップが含まれているかを指定します。ユーザーがログインすると、DefectDojo はこの属性を読み取り、一致するグループにユーザーを割り当てます。アサーションから考慮するグループを制限するには、**Group Limiter Regex Expression** フィールドを使用します。これはアサーションのグループ名に適用される正規表現で、DefectDojo が処理対象とするグループを絞り込むために使用されます。

この値は、名前空間のプレフィックスを含め、ID プロバイダーがアサーション内で発行する属性名と正確に一致している必要があります。`groups` のような短くわかりやすい名前は、IdP がその文字どおりの属性名を発行するように設定されている場合にのみ機能します。多くの IdP は代わりに完全修飾クレーム URI を使用します。

### Group Name Attribute by Identity Provider

| Identity Provider | Default attribute name to use |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups`(SAML アプリの Group Attribute Statement で設定した属性名) |
| **Keycloak** | `groups`(または Group List マッパーの「SAML Attribute Name」に設定した値) |
| **PingFederate / generic** | IdP 側で設定した値。`groups` だと決めつける前に IdP のアサーションを確認してください |

グループマッピングが何も行っていないように見える場合(ユーザーは正常にログインできるが、グループが作成または割り当てられない場合)は、下記の [Troubleshooting → SAML group mapping does nothing](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) を参照してください。

一致する名前のグループが存在しない場合、DefectDojo は自動的にグループを作成し、そのメンバーに **Reader** ロールを割り当てます。この Reader ロールは、メンバーの*グループ自体へのアクセス*を管理するものであり、配下の製品、製品タイプ、その他の組織アセットへのアクセスを付与するものではない点に注意してください。それらの権限は別途設定する必要があり、Superuser が該当する製品または製品タイプに対してグループにロールを割り当てるまで、新しく自動作成されたグループにはそれらの権限は一切ありません。

グループマッピングを有効にするには、フォームの下部にある **Enable Group Mapping** チェックボックスをオンにします。

## Default access for SSO-provisioned users

SAML(または他のソーシャル認証プロバイダー)経由で新しいユーザーが作成され、SAML Group Mapping によってどのグループにも追加されなかった場合、そのユーザーは**権限が一切ない**状態で DefectDojo インスタンスにアクセスすることになります。ログインすると、製品タイプ、製品、エンゲージメントがいずれもゼロ件と表示され、ダッシュボードは空に見えます。

新しくプロビジョニングされるすべての SSO ユーザーに適切なベースラインを与えるには、System Settings ページで **Default group** と **Default group role** を設定します。

1. **⚙️ Configuration → System Settings**(Superuser のみ)を開きます。
2. **Default group** に、新しく作成されたユーザーが参加すべき [User Group](../../user_management/create_user_group/) を設定します。
3. **Default group role** に、そのグループでユーザーが持つべきロール(例: **Reader**)を設定します。
4. 必要に応じて、**Default group email pattern** に正規表現(例: `.*@yourcompany\.com$`)を設定し、メールアドレスが一致するユーザーにのみデフォルトグループが適用されるようにします。
5. 保存します。

**Default group** と **Default group role** の両方を設定する必要があります。どちらかが空の場合、デフォルトグループは適用されません。

この設定は Django のユーザー作成シグナル上で動作するため、特定の認証バックエンドの内部だけでなく、SAML、OAuth、その他のソーシャル認証プロバイダー経由で作成されたユーザーを含む**新しく作成されたすべてのユーザー**に適用されます。

> **既存のユーザーには影響しません。** デフォルトグループは、ユーザーが最初に作成されたときにのみ適用されます。この設定を後で変更しても、既存の DefectDojo ユーザーは現在のグループメンバーシップを維持します。

## Cloud vs On-Premise Differences

DefectDojo Cloud は、DefectDojo On-Prem と同レベルの SAML カスタマイズをサポートしていません。設定できる変数は UI 経由のもののみです。主な違いは次のとおりです。

| Capability | Cloud | On-Premise |
|---|---|---|
| **ユーザー名のマッチング** | NameID のみ | NameID のみ(`SAML_USE_NAME_ID_AS_USERNAME` 環境変数はオープンソース版にのみ適用され、Pro には適用されません) |
| **SAML アサーションの暗号化** | 現在サポートされていません | 現在サポートされていません |
| **SAML ログインログ** | UI では利用できません。ログの取得はサポートにお問い合わせください。 | アプリケーションコンテナのログ(`docker logs dojo`)から利用可能です |
| **設定方法** | Enterprise Settings UI のみ | Enterprise Settings UI、Django Admin、または Django Shell |
| **環境変数** | 顧客が直接設定することはできません。変更が必要な場合はサポートにお問い合わせください。 | `dojo-compose-cli environment add` で設定可能です |

NameID 以外の属性(`uid` や `email` など)でユーザーを照合する必要がある場合は、DefectDojo の設定を調整するのではなく、目的の値を NameID として送信するように ID プロバイダー側を設定してください。

## Troubleshooting

### SAML Debugging output

([Additional Options](#additional-options) の)**Enable SAML Debugging** をチェックすると、DefectDojo は IdP から受信した生の属性を含む詳細な SAML 処理の出力を、`saml2` ロガー配下の `DEBUG` レベルでアプリケーションログに書き込みます。

| Where you're running | Where to read the debug output |
|---|---|
| **DefectDojo Cloud** | SAML デバッグログは UI では公開されていません。特定の期間のログが必要な場合は DefectDojo サポートにお問い合わせください。 |
| **On-Premise(単一コンテナ)** | `docker logs dojo`(または Helm/K8s のログ集約) |
| **On-Premise(Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi`(またはクラスターのログアグリゲーター) |

トラブルシューティングが終わったら、このオプションは**オフ**にしてください。SAML デバッグログは詳細であり、IdP からの機密性の高い属性値が含まれる場合があります。

### Users get a "User not found" or "Permission denied" error after a successful IdP login

SAML アサーションの解析は成功している(XML や署名のエラーがない)にもかかわらず DefectDojo がログインを拒否する場合、最も多い原因は IdP と DefectDojo の間の**ユーザー名の不一致**です。

DefectDojo は、SAML ログインを既存のアカウントに照合する際、**ユーザー名で**ユーザーを検索します。IdP が `username` 属性として送信する値が、既存の DefectDojo ユーザーのユーザー名と一致しない場合、アサーションの他の部分が有効であっても検索は失敗します。

対処法は 2 つあります。環境に合ったほうを選んでください。

- **Attribute Mapping から `username` を削除する** — DefectDojo が代わりに SAML の `NameID` をユーザー名として使用するようにフォールバックさせます。DefectDojo のユーザー名が、IdP が発行する NameID の形式とすでに一致している場合に適しています。
- **ユーザー名を一致させる。** DefectDojo のユーザー名が、IdP が `username` クレームで送信する値と正確に一致するようにします。ほとんどの組織にとって最も簡単な方法は、DefectDojo のユーザー名をユーザーのメールアドレスと同じにし、IdP がそのメールアドレスを `username` クレームとして送信するようにすることです。

IdP が実際に何を送信しているかわからない場合は、(上記の)**Enable SAML Debugging** を有効にして、ログで解析済みの属性を確認してください。

### SAML group mapping does nothing — users log in but no groups are assigned

最も多い原因は、**Group Name Attribute** フィールドと、IdP が実際に送信している属性名との不一致です。上記の [Group Name Attribute by Identity Provider](#group-name-attribute-by-identity-provider) の表を参照し、**Enable SAML Debugging** を有効にして IdP から返される生の属性を確認してください。
