---
title: OIDC
description: DefectDojo Pro で OpenID Connect (OIDC) SSO を設定する
weight: 17
audience: pro
---

DefectDojo Pro は、汎用の OpenID Connect (OIDC) プロバイダーを介したログインをサポートしています。オープンソース版の DefectDojo には SSO は含まれていません。オープンソース版のアクセス制御については [Authorized Users](/admin/user_management/os__authorized_users/) を参照してください。

## Configuration

DefectDojo で **Enterprise Settings > OIDC Settings** に移動します。

![image](images/oidc_pro.png)

フォームに入力します。

1. **Endpoint** — OIDC プロバイダーのベース URL です。`/.well-known/openid-configuration` は含めないでください。
2. **Client ID** — OIDC クライアント ID です。
3. **Client Secret** — OIDC クライアントシークレットです。
4. 必要に応じて **Claim Mapping** と **Group Mapping** を設定します。詳細は後述します。
5. **Enable OIDC** をチェックします。

フォームを送信します。DefectDojo のログインページに **Log In With OIDC** ボタンが表示されます。

いつでも **Validate Config** を使用して、設定を保存せずに確認できます。これはディスカバリードキュメントを取得し、署名鍵と発行者を検証し、プロバイダー側に登録すべき正確なリダイレクト URI を表示し、クレームおよびグループのマッピングをプロバイダーが公開しているクレームと突き合わせます。

## Claim Mapping

各行は、1 つの **OIDC Claim** を、それが値を設定する **DefectDojo Field** にマッピングします。行を追加するには **Add Claim Mapping** を使用し、削除するにはゴミ箱アイコンを使用します。

![image](images/sso_oidc_claim_mapping.png)

行が設定されていないフィールドは標準のクレームを使用するため、このセクションはプロバイダーが異なる名前を使用している場合にのみ必要です。標準のクレームは次のとおりです。

| DefectDojo Field | Standard claim |
| --- | --- |
| Username | `preferred_username` |
| Email | `email` |
| First Name | `given_name` |
| Last Name | `family_name` |

メモ:

- 未設定のインスタンスでは、これら 4 つの行があらかじめ入力された状態で開くため、変更を加える前に OIDC がどのように動作するかを確認できます。
- 同じクレームを複数のフィールドに使用できます。ただし、各 DefectDojo フィールドにマッピングできるクレームは 1 つだけです。
- クレームは ID トークンと userinfo レスポンスの両方から読み取られるため、プロバイダーがどちらか一方でしか公開していないクレームでも機能します。
- マッピングされたクレームが特定のユーザーで欠落または空の場合、そのフィールドは空にされるのではなく標準の値を保持します。

## Group Mapping

DefectDojo は、ログインのたびにプロバイダーが報告するグループを DefectDojo のグループにミラーリングできます。設定を表示するには **Enable Group Mapping** をチェックします。

![image](images/sso_oidc_group_mapping.png)

- **Group Claim Name** — ユーザーのグループを含むクレームです。**多くのプロバイダーはデフォルトではこれを発行しない**ため、明示的にマッパーを設定する必要があります。たとえば Keycloak では、クライアントに *Group Membership* マッパーを追加します。なお、*User Realm Role* マッパーはグループではなくレルムの**ロール**を送信する点に注意してください。
- **Group Limiter Regex Expression** — この式に一致するグループのみがミラーリングされます。すべてを許可するには `.*` を使用します。
- **Remove Stale Group Memberships** — 有効にすると、プロバイダーが報告しなくなった OIDC プロビジョニングのグループのメンバーシップは、次回のログイン時に削除されます。影響を受けるのは OIDC によって作成されたグループのみです。手動で割り当てたグループや、SAML など別のプロバイダーによってプロビジョニングされたグループが変更されることはありません。

グループは初回使用時に作成され、プロバイダーが報告する名前がそのまま使用されます。プロバイダーが完全なグループパスを送信する場合(Keycloak の *Group Membership* マッパーで **Full group path** を有効にするとこうなります)、DefectDojo のグループ名は `Group A` ではなく `/Group A` になります。別のプロバイダーから届くグループと名前を一致させたい場合は、このオプションをオフにしてください。そうしないと、同じ論理グループに対して 2 つの DefectDojo グループができてしまいます。

グループマッピングが何も行っていないように見える場合は、**Validate Config** を実行してください。指定したクレームがプロバイダーによって公開されているかどうかが報告されます。
