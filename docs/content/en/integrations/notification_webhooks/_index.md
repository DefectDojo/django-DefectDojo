---
title: "Notification Webhooks"
description: "..."
weight: 7
chapter: true
---

## Transition graph:

```mermaid
flowchart TD

    START{{Endpoint created}}
    ALL{All states}
    STATUS_ACTIVE([STATUS_ACTIVE])
    STATUS_INACTIVE_TMP
    STATUS_INACTIVE_PERMANENT
    STATUS_ACTIVE_TMP([STATUS_ACTIVE_TMP])
    END{{Endpoint removed}}

    START ==> STATUS_ACTIVE
    STATUS_ACTIVE --HTTP 200 or 201 --> STATUS_ACTIVE
    STATUS_ACTIVE --HTTP 5xx <br>or HTTP 429 <br>or Timeout--> STATUS_INACTIVE_TMP
    STATUS_ACTIVE --Any HTTP 4xx response<br>or any other HTTP responsee<br>or non-HTTP error--> STATUS_INACTIVE_PERMANENT
    STATUS_INACTIVE_TMP -.After 60s.-> STATUS_ACTIVE_TMP
    STATUS_ACTIVE_TMP --HTTP 5xx <br>or HTTP 429 <br>or Timeout <br>within 24h<br>from the first error-->STATUS_INACTIVE_TMP
    STATUS_ACTIVE_TMP -.After 24h.-> STATUS_ACTIVE
    STATUS_ACTIVE_TMP --HTTP 200 or 201 --> STATUS_ACTIVE_TMP
    STATUS_ACTIVE_TMP --HTTP 5xx <br>or HTTP 429 <br>or Timeout <br>within 24h from the first error<br>or any other HTTP respons or error--> STATUS_INACTIVE_PERMANENT
    ALL ==Activation by user==> STATUS_ACTIVE
    ALL ==Deactivation by user==> STATUS_INACTIVE_PERMANENT
    ALL ==Removal of endpoint by user==> END
```

Notes: 

1. Transitions:
    - bold: manual changes by user
    - dotted: automated by celery
    - others: based on responses on webhooks
1. Nodes:
    - Stadium-shaped: Active - following webhook can be send
    - Rectangles: Inactive - performing of webhook will fail (and not retried)
    - Hexagonal: Initial and final states
    - Rhombus: All states (meta node to make graph more readable)
