---
title: "Event: product_added"
weight: 2
chapter: true
---

## Event HTTP header
```yaml
X-DefectDojo-Event: product_added
```

## Event HTTP body
```json
{
    "description": null,
    "product": {
        "id": 4,
        "name": "notif prod"
    },
    "product_type": {
        "id": 4,
        "name": "notif prod type"
    },
    "url": "http://localhost:8080/product/4",
    "user": null
}
```