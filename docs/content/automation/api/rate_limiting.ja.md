---
title: レート制限
description: ブルートフォース攻撃を軽減するため、ログインページのレート制限を設定する
weight: 4
audience: opensource
aliases:
- /ja/en/open_source/rate_limiting
---

DefectDojoには、ブルートフォース攻撃から保護するためのログインページのレート制限機能が含まれており、[Django Ratelimit](https://django-ratelimit.readthedocs.io/en/stable/index.html)によって実現されています。

## Configuration

レート制限は以下の設定によって構成されます(これらの適用方法については[Configuration](/get_started/open_source/configuration/)を参照してください):

```python
DD_RATE_LIMITER_ENABLED=(bool, True),
DD_RATE_LIMITER_RATE=(str, '5/m'),
DD_RATE_LIMITER_BLOCK=(bool, True),
DD_RATE_LIMITER_ACCOUNT_LOCKOUT=(bool, True),
```

### Rate Limit (`DD_RATE_LIMITER_RATE`)

リクエストを制限する頻度を設定します。サポートされている単位:

- 秒: `1s`
- 分: `5m`
- 時間: `100h`
- 日: `2400d`

より詳細な設定オプションについては、[Django Ratelimit rates docs](https://django-ratelimit.readthedocs.io/en/stable/rates.html)を参照してください。

### Block Requests (`DD_RATE_LIMITER_BLOCK`)

デフォルトでは、レート制限は違反を記録しますが、リクエストをブロックしません。`DD_RATE_LIMITER_BLOCK`を`True`に設定すると、設定されたレートを超過した時点で、すべての受信リクエストが積極的にブロックされるようになります。

### Account Lockout (`DD_RATE_LIMITER_ACCOUNT_LOCKOUT`)

有効にすると、ログイン試行がレート制限をトリガーしたユーザーは、再度ログインする前にパスワードのリセットを求められます。これにより、ブルートフォース攻撃時における認証情報漏洩のリスクが軽減されます。

## Multi-Process Behaviour

複数の`uwsgi`プロセスで実行している場合、レート制限パッケージは各プロセスに固有のメモリベースのキャッシュを使用します。このデフォルト設定では、レート制限のカウンターはプロセス間で共有されません。
