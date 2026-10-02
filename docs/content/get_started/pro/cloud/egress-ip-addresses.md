---
title: "Egress IP Addresses"
description: "The outbound IP addresses DefectDojo Cloud connects from, for allowlisting in your external firewalls."
weight: 5
audience: pro
---

When DefectDojo Cloud reaches out to your systems — Connectors syncing a scanner's
API, pushing issues to Jira or ServiceNow, sending notification webhooks, or
delivering email over SMTP — those connections are **initiated outbound** from
your DefectDojo environment. If the system on the other end sits behind a
firewall, you'll need to allow DefectDojo's outbound (egress) IP addresses so
those connections aren't blocked.

This page lists where to find those egress IP addresses.

## Egress vs. ingress

These are two different things, and this page covers only the first:

- **Egress (this page)** — the source IP addresses DefectDojo Cloud connects
  **from** when it reaches **out** to *your* external systems. Allowlist these in
  **your** firewalls so DefectDojo can reach the systems it integrates with.
- **Ingress** — the rules that control who is allowed to reach **your** DefectDojo
  instance. Those are managed as Firewall Rules in the Cloud Manager, not here.
  See [Connectivity Troubleshooting](../connectivity-troubleshooting/) and the
  Firewall Rules step in
  [Set up an additional Cloud instance](../additional-cloud-instance/).

## Multi-tenant deployments

Standard, Pay-as-you-go, and Premium instances run on shared, regional
Google Kubernetes Engine (GKE) clusters. Outbound connections come from the
external IP addresses of the nodes in the region your instance runs in.

The current set of node egress IPs is published as a JSON feed, grouped by
region:

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

The feed looks like this:

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

To allowlist DefectDojo's egress traffic:

1. Identify the region your instance runs in (the Server Location you selected
   when the instance was provisioned).
2. Allow every IP address listed under that region. Each entry is a `/32`
   (single-host) CIDR.

**This list changes over time.** Nodes are added and replaced as the platform
autoscales, so the set of egress IPs for a region is not fixed. Treat the JSON
feed as the source of truth rather than copying the addresses once:

- Pull the feed programmatically and refresh your firewall allowlist from it on a
  schedule, or
- Re-check the feed and reconcile your rules periodically.

If your firewall can't track a changing list and you need a small, stable set of
addresses, talk to your DefectDojo representative about a **Dedicated** instance
(see below).

## Single-tenant (Dedicated) deployments

A **Dedicated**-tier instance runs in its own GCP project and VPC, and its
egress IP address is **stable** — it's assigned when the instance is provisioned
and does not change as the platform scales.

Because it's tied to your specific instance, the stable egress IP isn't published
in the public feed. Contact [support@defectdojo.com](mailto:support@defectdojo.com)
to get the egress IP address(es) assigned to your Dedicated instance, and
allowlist those in your external firewalls.

*Have a question this page doesn't answer? Contact your DefectDojo
representative.*
