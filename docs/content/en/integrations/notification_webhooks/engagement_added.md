---
title: "Event: engagement_added"
weight: 3
chapter: true
---

## Event HTTP header
```yaml
X-DefectDojo-Event: engagement_added
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
    "url": "http://localhost:8080/engagement/7",
    "user": null
}
```