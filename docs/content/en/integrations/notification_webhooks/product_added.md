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
    "user": null
}
```
