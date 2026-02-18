---
title: "Event: ping"
weight: 7
chapter: true
exclude_search: true
aliases:
  - /en/open_source/notification_webhooks/ping
---
An event `ping` is sent during Webhook setup to test whether the endpoint is up and responding with the expected status code.

## Event HTTP header
```yaml
X-DefectDojo-Event: ping
```

## Event HTTP body
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
    },
}
```
