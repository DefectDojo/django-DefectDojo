---
title: "Event: test_added"
weight: 5
chapter: true
---

## Event HTTP header
```yaml
X-DefectDojo-Event: test_added
```

## Event HTTP body
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
    "user": null
}
```
