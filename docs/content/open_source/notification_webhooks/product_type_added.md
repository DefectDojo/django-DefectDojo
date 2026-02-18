---
title: "Event: product_type_added"
weight: 2
chapter: true
exclude_search: true
aliases:
  - /en/open_source/notification_webhooks/product_type_added
---
## Event HTTP header
```yaml
X-DefectDojo-Event: product_type_added
```

## Event HTTP body
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
