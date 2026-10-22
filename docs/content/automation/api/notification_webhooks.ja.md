---
title: 通知Webhook
description: DefectDojoのイベント発生時に、外部サーバーへHTTP Webhook通知を送信する
weight: 8
audience: opensource
aliases:
- /ja/en/open_source/notification_webhooks/how_to
---

**これは実験的なオープンソース機能です — 今後のリリースで動作が変更される可能性があります。**

Webhookは、特定のイベントが発生するたびに、DefectDojoインスタンスからユーザー定義のサーバーへ送信されるアウトバウンドHTTPリクエストです。

## Setup

Webhookエンドポイントは管理者が設定します。Webhookが作成されると、DefectDojoはエンドポイントに到達可能であり、期待されるステータスコードを返すことを確認するために[`ping`](#ping)イベントを送信します。

## Endpoint State Transitions

DefectDojoは配信の成功状況を監視し、HTTPレスポンスやネットワーク障害に基づいてエンドポイントを一時的または恒久的に無効化します。管理者による手動での再有効化も可能です。

- **スタジアム型の状態**: アクティブ — Webhookを送信できます
- **矩形の状態**: 非アクティブ — Webhookの配信は失敗し、再試行されません
- **状態遷移のトリガー**: 対象サーバーからのHTTPレスポンス、celeryの自動処理、または管理者による手動操作

## Request Headers

すべてのWebhookリクエストには、以下のヘッダーが含まれます:

```yaml
User-Agent: DefectDojo-<version>
X-DefectDojo-Event: <event_name>
X-DefectDojo-Instance: <base_url_of_dd_instance>
```

## Events

### product_type_added

新しい製品タイプが作成されたときに発火します。

**Header:**
```yaml
X-DefectDojo-Event: product_type_added
```

**Body:**
```json
{
    "description": "",
    "title": "",
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/product_types/4/",
    "url_ui": "http://localhost:8080/product/type/4",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### product_added

新しい製品が作成されたときに発火します。

**Header:**
```yaml
X-DefectDojo-Event: product_added
```

**Body:**
```json
{
    "description": "",
    "title": "",
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/products/4/",
    "url_ui": "http://localhost:8080/product/4",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### engagement_added

新しいエンゲージメントが作成されたときに発火します。

**Header:**
```yaml
X-DefectDojo-Event: engagement_added
```

**Body:**
```json
{
    "description": "",
    "title": "",
    "engagement": {
        "id": 7,
        "name": "notif eng",
        "url_api": "http://localhost:8080/api/v2/engagements/7/",
        "url_ui": "http://localhost:8080/engagement/7"
    },
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/engagements/7/",
    "url_ui": "http://localhost:8080/engagement/7",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### test_added

新しいテストが作成されたときに発火します。

**Header:**
```yaml
X-DefectDojo-Event: test_added
```

**Body:**
```json
{
    "description": "",
    "title": "",
    "engagement": {
        "id": 7,
        "name": "notif eng",
        "url_api": "http://localhost:8080/api/v2/engagements/7/",
        "url_ui": "http://localhost:8080/engagement/7"
    },
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "test": {
        "id": 90,
        "title": "notif test",
        "url_api": "http://localhost:8080/api/v2/tests/90/",
        "url_ui": "http://localhost:8080/test/90"
    },
    "url_api": "http://localhost:8080/api/v2/tests/90/",
    "url_ui": "http://localhost:8080/test/90",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### scan_added / scan_added_empty

スキャンがインポートまたは再インポートされたときに発火します。`scan_added_empty`は、再インポートの結果、変更が発生しなかった場合(検出事項が新規作成もクローズもされなかった場合)に発火します。

**Headers:**
```yaml
X-DefectDojo-Event: scan_added
```
```yaml
X-DefectDojo-Event: scan_added_empty
```

**Body:**
```json
{
    "description": "",
    "title": "",
    "engagement": {
        "id": 7,
        "name": "notif eng",
        "url_api": "http://localhost:8080/api/v2/engagements/7/",
        "url_ui": "http://localhost:8080/engagement/7"
    },
    "finding_count": 4,
    "findings": {
        "mitigated": [
            {
                "id": 233,
                "severity": "Medium",
                "title": "Mitigated Finding",
                "url_api": "http://localhost:8080/api/v2/findings/233/",
                "url_ui": "http://localhost:8080/finding/233"
            }
        ],
        "new": [
            {
                "id": 232,
                "severity": "Critical",
                "title": "New Finding",
                "url_api": "http://localhost:8080/api/v2/findings/232/",
                "url_ui": "http://localhost:8080/finding/232"
            }
        ],
        "reactivated": [
            {
                "id": 234,
                "severity": "Low",
                "title": "Reactivated Finding",
                "url_api": "http://localhost:8080/api/v2/findings/234/",
                "url_ui": "http://localhost:8080/finding/234"
            }
        ],
        "untouched": [
            {
                "id": 235,
                "severity": "Info",
                "title": "Untouched Finding",
                "url_api": "http://localhost:8080/api/v2/findings/235/",
                "url_ui": "http://localhost:8080/finding/235"
            }
        ]
    },
    "product": {
        "id": 4,
        "name": "notif prod",
        "url_api": "http://localhost:8080/api/v2/products/4/",
        "url_ui": "http://localhost:8080/product/4"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "test": {
        "id": 90,
        "title": "notif test",
        "url_api": "http://localhost:8080/api/v2/tests/90/",
        "url_ui": "http://localhost:8080/test/90"
    },
    "url_api": "http://localhost:8080/api/v2/tests/90/",
    "url_ui": "http://localhost:8080/test/90",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

---

### ping

Webhookのセットアップ時に、エンドポイントへの到達可能性を確認するために送信されます。

**Header:**
```yaml
X-DefectDojo-Event: ping
```

**Body:**
```json
{
    "description": "Test webhook notification",
    "title": "",
    "user": {
        "id": 1,
        "email": "admin@defectdojo.local",
        "first_name": "Admin",
        "last_name": "User",
        "username": "admin",
        "url_api": "http://localhost:8080/api/v2/users/1/",
        "url_ui": "http://localhost:8080/user/1"
    }
}
```

## Roadmap

計画されている既知の改善事項:

- SLA関連イベント(まだサポートされていません)
- ユーザー定義のWebhook(現在は管理者のみ設定可能)
- Webhookエンドポイント向けのフィルタリングとページネーションを備えたUIの改善
