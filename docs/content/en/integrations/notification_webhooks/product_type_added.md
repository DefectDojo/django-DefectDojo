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
        "name": "notif prod type",
        "url_api": "http://localhost:8080/api/v2/product_types/4/",
        "url_ui": "http://localhost:8080/product/type/4"
    },
    "url_api": "http://localhost:8080/api/v2/product_types/4/",
    "url_ui": "http://localhost:8080/product/type/4",
    "user": null
}
```