---
title: "Event: test_added"
weight: 4
chapter: true
---

## Event HTTP header
```yaml
X-DefectDojo-Event: test_added
```

## Event HTTP body
```json
{
    "description": null,
    "engagement": {
        "id": 7,
        "name": "notif eng"
    },
    "product": {
        "id": 4,
        "name": "notif prod"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type"
    },
    "test": {
        "id": 90,
        "title": "notif test"
    },
    "url": "http://localhost:8080/test/90",
    "user": null
}
```