---
title: "Event: ping"
weight: 7
chapter: true
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
    "user": null,
}
```
