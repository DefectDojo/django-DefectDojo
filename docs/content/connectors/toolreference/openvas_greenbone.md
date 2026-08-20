---
title: "OpenVAS / Greenbone"
description: "How to set up the OpenVAS / Greenbone Upstream Connector for DefectDojo"
weight: 98
audience: pro
---
The OpenVAS / Greenbone connector imports **network vulnerability findings** from a Greenbone (Greenbone Community Edition or Greenbone Enterprise) instance. It talks to `gvmd` over **GMP (Greenbone Management Protocol)** — an XML protocol over a TLS socket, not HTTP — and syncs the whole instance: it enumerates scan **tasks** and creates a DefectDojo product for each, importing the results of each task's latest report.

#### Prerequisites

A Greenbone **GMP user** (username + password) and network access to gvmd's GMP TLS port (default **9390**). The Greenbone Community Edition compose stack fronts gvmd via a unix socket, so to reach it from a networked connector you either run the connector where it can reach the socket or expose the GMP TLS port (for example a `socat` TLS bridge to `gvmd.sock`).

#### Connector Mappings

1. Enter the gvmd host in the **Location** field (host or `host:port`).
2. Enter the GMP **Username** and **Password**.
3. Optionally set the **GMP Port** (defaults to 9390).
4. For gvmd's default self\-signed certificate, either provide a **CA Certificate (PEM)** to verify against, or set **Skip TLS Verification** to `true`.
5. Optionally, set a **Minimum Severity** to limit which findings are imported.

Each Greenbone task becomes a Record. Findings come from the task's latest finished report — one per `<result>`. Severity is taken from the result's threat level (Greenbone's `Log`/`Debug` informational levels map to Info), with the numeric CVSS score recorded; CVE references become vulnerability ids, the NVT solution becomes the mitigation, and each result's host/port becomes an endpoint.
