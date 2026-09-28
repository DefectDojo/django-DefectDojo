---
title: Authorization Connectors
description: '1つのページですべてのIDプロバイダーを確認: 設定済みか、有効か、どのプロトコルを使用しているか'
weight: 1
audience: pro
---

Authorization Connectorsは、DefectDojo Proが対応するすべてのIDプロバイダーと、それぞれの状態、使用しているプロトコルを1つのページにまとめて表示します。これが存在する前は、各プロバイダーはそれぞれ独自の設定フォームに存在しており、すべてを開かない限り「このインスタンスで何が設定されているか」に答える方法がありませんでした。

Authorization Connectorsは**DefectDojo Pro**の機能です。**Connect > Authorization**にあります。IDプロバイダーの設定を表示・変更できるのは**スーパーユーザー**のみです。

![Authorization Connectors](images/authorization_connectors.png)

## How the page is organised

プロバイダーは2つのセクションに分かれており、それぞれ見出しの横に件数が表示され、アルファベット順に並んでいます。

* **Configured Providers**(設定済みプロバイダー) — 現在オンになっているかどうかにかかわらず、このインスタンスで設定済みのプロバイダー
* **Available Providers**(利用可能なプロバイダー) — サポートされているが、まだ設定されていないプロバイダー

この区分はあえて*enabled*(有効)ではなく*configured*(設定済み)を基準にしています。設定した後にオフに切り替えられたプロバイダーはConfigured Providersに残ります。設定した本人がそこを探すはずだからです。状態はタイル上に表示されます。

各タイルには次の情報が表示されます。

| | |
| --- | --- |
| **Logo and name** | プロトコル名を含まない、プロバイダーの名称 |
| **Protocol tag** | `SAML 2.0`、`OAuth 2.0`、`OpenID Connect`、`LDAP`のいずれか |
| **Status tag** | `Enabled`、`Disabled`、`Not configured`のいずれか |
| **`BETA` tag** | まだベータ版であるプロバイダーに表示 |
| **Action** | 設定済みプロバイダーには**Manage Configuration**、未設定のプロバイダーには**Configure** |

どちらのセクションにも、プロバイダー名とプロトコルの両方に一致する検索ボックスがあります。たとえば`oauth`で検索すると、OAuthプロバイダーだけに絞り込まれます。

![Available providers](images/authorization_available.png)

## One configuration per provider

IDプロバイダーの設定は、インスタンスごと・プロバイダーごとに1組の値です。Oktaアプリケーションは1つ、SAML IDプロバイダーは1つ、LDAPディレクトリは1つです。タイルにもそのように表示され、「追加」という操作はありません。プロバイダーの設定方法を変更するには、既存の設定を編集します。

この点が、1つのツールについて複数の設定を並べて持てる[コネクタギャラリー](/connectors/upstream/about/)とAuthorization Connectorsの違いです。

## The three states, and what they mean

| Status | Meaning | What to do next |
| --- | --- | --- |
| **Enabled** | 設定済みでサインインを受け付けている | 対応不要 |
| **Disabled** | 設定済みだがオフに切り替えられている — ログインページにボタンは表示されない | 元に戻したい場合は設定画面から再度有効化 |
| **Not configured** | サポートされているが、まだ何も入力されていない | **Configure**で設定を行う |

プロバイダーを選択すると、そのプロバイダー自体の設定フォームが直接開きます。中間的なプロバイダー選択画面はありません。

## Supported providers

| Provider | Protocol | Setup guide |
| --- | --- | --- |
| Auth0 | OAuth 2.0 | [Auth0](/admin/sso/pro__auth0/) |
| GitHub Enterprise | OAuth 2.0 | [GitHub Enterprise](/admin/sso/pro__github_enterprise/) |
| GitLab | OAuth 2.0 | [GitLab](/admin/sso/pro__gitlab/) |
| Google | OAuth 2.0 | [Google](/admin/sso/pro__google/) |
| Keycloak | OAuth 2.0 | [KeyCloak](/admin/sso/pro__keycloak/) |
| LDAP | LDAP | [LDAP](/admin/sso/pro__ldap/) |
| Microsoft Entra ID | OAuth 2.0 | [Azure Active Directory](/admin/sso/pro__azure_ad/) |
| Okta | OAuth 2.0 | [Okta](/admin/sso/pro__okta/) |
| OpenID Connect | OpenID Connect | [OIDC](/admin/sso/pro__oidc/) |
| SAML | SAML 2.0 | [SAML](/admin/sso/pro__saml/) |

このページはプロバイダーの設定の*状態*のみを表示します。設定内のシークレット、すなわちクライアントシークレット、バインドパスワード、証明書はこのページの背後にあるデータには含まれず、読み出すこともできません。

## When a provider will not connect

Authorization Connectorsは何が設定されているかを示しますが、失敗したサインインは表示しません。それらは[Diagnostics](/admin/diagnostics/pro__diagnostics/)に記録されており、SSO、SAML、LDAPがそれぞれ、拒否された理由(不正なアサーション署名、拒否されたバインド、一致しない属性など)とともに自身の試行を報告します。これらの行はインスタンスレベルの情報であるため、スーパーユーザーのみが閲覧できます。

フォールバックとして、ユーザー名とパスワードを持つスーパーユーザーアカウントを少なくとも1つ維持してください。また、IDプロバイダーが動作しなくなった場合は`/login?force_login_form`で標準のログインフォームに戻れることを覚えておいてください。両方について[Single Sign-On](/admin/sso/)を参照してください。

## Related

* [Single Sign-On](/admin/sso/) — プロバイダーごとのセットアップガイドとログイン設定
* [Diagnostics](/admin/diagnostics/pro__diagnostics/) — サインインの試行が失敗した理由
* [Connectors](/connectors/upstream/about/) — このページのモデルとなったアップストリームギャラリー
