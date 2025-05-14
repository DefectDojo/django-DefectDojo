---
title: "Notification Webhooks Setup"
weight: 1
chapter: true
---

Webhooks are HTTP requests coming from the DefectDojo instance towards a user-defined webserver which expects this kind of incoming traffic.

## Transition graph:

It is not unusual that in some cases a webhook can not be delivered. It is usually connected to network issues, server misconfiguration, or running upgrades on the server. DefectDojo needs to react to these outages. It might temporarily or permanently disable related endpoints. The following graph shows how it might change the status of the webhook definition based on HTTP responses (or manual user interaction).

```kroki {type=mermaid}
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
    STATUS_ACTIVE --Any HTTP 4xx response<br>or any other HTTP response<br>or non-HTTP error--> STATUS_INACTIVE_PERMANENT
    STATUS_INACTIVE_TMP -.After 60s.-> STATUS_ACTIVE_TMP
    STATUS_ACTIVE_TMP --HTTP 5xx <br>or HTTP 429 <br>or Timeout <br>within 24h<br>from the first error-->STATUS_INACTIVE_TMP
    STATUS_ACTIVE_TMP -.After 24h.-> STATUS_ACTIVE
    STATUS_ACTIVE_TMP --HTTP 200 or 201 --> STATUS_ACTIVE_TMP
    STATUS_ACTIVE_TMP --HTTP 5xx <br>or HTTP 429 <br>or Timeout <br>within 24h from the first error<br>or any other HTTP response or error--> STATUS_INACTIVE_PERMANENT
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
    - Stadium-shaped: Active - following webhook can be sent
    - Rectangles: Inactive - performing of webhook will fail (and not retried)
    - Hexagonal: Initial and final states
    - Rhombus: All states (meta node to make the graph more readable)

## Body and Headers

The body of each request is JSON which contains data about related events like names and IDs of affected elements.
Examples of bodies are on pages related to each event (see below).

Each request contains the following headers. They might be useful for better handling of events by the server receiving them.

```yaml
User-Agent: DefectDojo-<version of DD>
X-DefectDojo-Event: <name of the event>
X-DefectDojo-Instance: <Base URL for DD instance>
```
## Disclaimer

This functionality is new and in experimental mode. This means functionality might generate breaking changes in following DefectDojo releases and might not be considered final.

However, the community is open to feedback to make this functionality better and get it stable as soon as possible.

## Roadmap

There are a couple of known issues that are expected to be resolved as soon as core functionality is considered ready.

- Support events - Not only adding products, product types, engagements, tests, or upload of new scans but also events around SLA
- User webhook - right now only admins can define webhooks; in the future, users will also be able to define their own
- Improvement in UI - add filtering and pagination of webhook endpoints

## Events

- [`product_type_added`](../product_type_added)
- [`product_added`](../product_added)
- [`engagement_added`](../engagement_added)
- [`test_added`](../test_added)
- [`scan_added` and `scan_added_empty`](../scan_added)
- [`ping`](../ping)
