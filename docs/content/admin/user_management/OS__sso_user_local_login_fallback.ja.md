---
title: SSOユーザーのログインを再有効化する（オープンソース版）
description: SSOがPro限定機能であるオープンソース版に移行した後、SSOでプロビジョニングされたユーザーにローカルパスワードを付与する方法
audience: opensource
weight: 2
---

## この手順が該当するケース

SSO（SAML、OIDC、OAuth）は[DefectDojo Pro](https://defectdojo.com)の機能です。オープンソース版DefectDojo 3.xにアップグレードする（あるいは何らかの理由でProから離れる）と、SSOのログインオプションは削除され、SSO経由でプロビジョニングされていたユーザーはログインできなくなります。それらのアカウントにはローカルパスワードが一度も設定されていないため、UIやAPIから設定しようとしても、DefectDojoがそれらをSSOアカウントとして検出し、変更をブロックします。

これらのユーザーを削除して作り直す必要は**ありません**（それでは履歴、権限、オブジェクトの所有権が失われてしまいます）。代わりに、バックエンドで各アカウントにローカルパスワードを付与し、次回ログイン時にパスワードのリセットを強制してください。

SSOがPro限定である背景については、[SSOのセクション](/admin/sso/)と[3.0アップグレードノート](/releases/os_upgrading/3.0/#sso-providers-are-available-in-defectdojo-pro-only)を参照してください。

## 発生する理由

オープンソース版DefectDojoは、Djangoのローカルユーザーデータベースに対してのみ認証を行います。あるアカウントが「SSOユーザー」かどうかは、そのアカウントが使用可能なパスワードを持っているかどうかだけで判定されます。SSOでプロビジョニングされたアカウントは*使用不可能な*パスワードで作成されているため、次のようになります。

* ローカルログインは失敗します（チェックすべきパスワードが存在しないため）。
* UIおよびAPIの **Force password reset**（パスワードリセットの強制）コントロールはブロックされ、そのユーザーはSSO経由で認証されている旨のメッセージが表示されます。

実際のパスワードを設定すると、この両方の条件が同時に解消されます。アカウントはローカルでログインできるようになり、強制リセットフラグも設定できるようになります。

## 回避策

以下の手順は、`uwsgi` コンテナ内のDjangoシェルから実行します。

```bash
docker compose exec -it uwsgi ./manage.py shell
```

### 単一ユーザーの例

```python
from dojo.user.models import Dojo_User, UserContactInfo

u = Dojo_User.objects.get(username="alice@example.com")
u.set_password("<temporary-strong-password>")   # makes the account a local login account
u.save()

uci, _ = UserContactInfo.objects.get_or_create(user=u)
uci.force_password_reset = True                  # force a change on next login
uci.save()
```

## ユーザーが次に行うこと

仮パスワードは各ユーザーへ帯域外で届けてください（メール、チームのチャット、あるいは普段秘密情報を共有している方法など）。次回ログイン時、DefectDojoはユーザーを **Change Password**（パスワード変更）ページへリダイレクトし、自分自身のパスワードを設定するまで他のどこにも進めないようにします。設定が完了すると、強制リセットフラグは自動的に解除されます。

インスタンスで「I forgot my password」（パスワードを忘れた場合）のフローが有効になっており（`DD_FORGOT_PASSWORD`、デフォルトで有効）、メールが設定されている場合、アカウントが使用可能なパスワードを持つようになった後は、ユーザーはログインページの **I forgot my password** リンクを使い、仮パスワードを使わずにパスワードを設定することもできます。

## 補足

* **Kubernetes:** 代わりにDjangoのPod内でシェルを実行します。例: `kubectl exec -it deploy/defectdojo-django -c uwsgi -- ./manage.py shell`（デプロイメント名とコンテナ名は環境に合わせて調整してください）。
* 強力な使い捨てパスワードを選んでください。`force_password_reset = True` によりユーザーはそれを使い続けることができないため、1回のログインに耐えられれば十分です。
* ロックアウトされないよう、動作するローカル管理者アカウントを少なくとも1つは維持してください。
