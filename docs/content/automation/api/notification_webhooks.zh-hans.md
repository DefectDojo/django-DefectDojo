---
title: 通知 Webhook
description: 在 DefectDojo 事件发生时向外部服务器发送 HTTP webhook 通知
weight: 8
audience: opensource
aliases:
- /zh-hans/en/open_source/notification_webhooks/how_to
---

**这是一项实验性的开源功能 — 其行为可能会在未来版本中发生变化。**

Webhook 是在特定事件发生时，从您的 DefectDojo 实例发送到用户自定义服务器的出站 HTTP 请求。

## Setup

Webhook 端点由管理员配置。创建 webhook 时，DefectDojo 会发送一个 [`ping`](#ping) 事件，以验证该端点是否可访问，并返回预期的状态码。

## Endpoint State Transitions

DefectDojo 会监控投递成功情况，并根据 HTTP 响应或网络故障暂时或永久禁用某个端点。管理员也可以手动重新启用该端点。

- **体育场形状状态**：活动（Active）— 可以发送 webhook
- **矩形状态**：非活动（Inactive）— webhook 投递将失败，且不会重试
- **状态转换由以下因素驱动**：目标服务器返回的 HTTP 响应、celery 自动化任务，或管理员的手动操作

## Request Headers

每个 webhook 请求都包含以下请求头：

```yaml
User-Agent: DefectDojo-<version>
X-DefectDojo-Event: <event_name>
X-DefectDojo-Instance: <base_url_of_dd_instance>
```

## Events

### product_type_added

在创建新的产品类型时触发。

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

在创建新的产品时触发。

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

在创建新的测试活动时触发。

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

在创建新的测试时触发。

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

在导入或重新导入扫描时触发。当重新导入未产生任何变化（未创建或关闭任何发现项）时，将触发 `scan_added_empty`。

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

在设置 webhook 期间发送，用于验证该端点是否可访问。

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

已知的计划改进项：

- 与 SLA 相关的事件（尚不支持）
- 用户自定义的 webhook（目前仅限管理员使用）
- 改进 webhook 端点的用户界面，加入过滤和分页功能
