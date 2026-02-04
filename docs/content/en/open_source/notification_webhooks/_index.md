---
title: "Notification Webhooks (experimental)"
weight: 7
chapter: true
sidebar:
    collapsed: true
exclude_search: true
---

Note: This is an experimental Open-Source feature - results may vary.

Functionality might generate breaking changes in following DefectDojo releases and might not be considered final.

Webhooks are HTTP requests coming from the DefectDojo instance towards a user-defined webserver which expects this kind of incoming traffic.

## Events

- [`product_type_added`](./product_type_added)
- [`product_added`](./product_added)
- [`engagement_added`](./engagement_added)
- [`test_added`](./test_added)
- [`scan_added` and `scan_added_empty`](./scan_added)
- [`ping`](./ping)