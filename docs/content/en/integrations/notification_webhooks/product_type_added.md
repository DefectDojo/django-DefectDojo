---
title: "Event: product_type_added"
weight: 1
chapter: true
---

## Event HTTP header
```yaml
X-DefectDojo-Event: product_type_added
```

## Event HTTP body
```json
{
    "description": null,
    "product_type": {
        "id": 4,
        "name": "notif prod type"
    },
    "url": "http://localhost:8080/product/type/4",
    "user": null
}
```