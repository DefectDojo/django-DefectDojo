---
title: "OpenVAS / Greenbone"
description: "How to set up the OpenVAS / Greenbone Upstream Connector for DefectDojo"
weight: 98
audience: pro
---
The OpenVAS / Greenbone connector imports **network vulnerability findings** from a Greenbone (Greenbone Community Edition or Greenbone Enterprise) instance. It talks to `gvmd` over **GMP (Greenbone Management Protocol)** — an XML protocol, not HTTP — and syncs the whole instance: it enumerates scan **tasks** and creates a DefectDojo product for each, importing the results of each task's latest report.

GMP can be carried two ways, and which one you need depends on your Greenbone version:

* **SSH** — what Greenbone documents from **GOS 4** onwards, and the right choice for a current instance.
* **TLS** — gvmd's older transport on port **9390**. It was the default only through GOS 3.1, and a current Greenbone commonly exposes no TLS listener at all.

#### Prerequisites

A Greenbone **GMP user** (username + password) in all cases. The GMP user is always required: SSH only carries the connection to `gvmd`, and GMP still authenticates over it.

For the **SSH** transport, an SSH account on the Greenbone host that reaches `gvmd`, plus its host key fingerprint. Either arrangement works and the connector detects which one your host uses:

* An account whose forced command connects the session to `gvmd` — the arrangement Greenbone appliances ship, and the one `gvm-tools` uses. The default account name is `gmp`.
* An ordinary account permitted to forward to gvmd's unix socket (`AllowStreamLocalForwarding`), which suits self\-managed and containerised installs.

For the **TLS** transport, network access to gvmd's GMP TLS port (default **9390**). Note that the Greenbone Community Edition compose stack fronts `gvmd` with a unix socket and no TLS listener, so this transport needs something in front of the socket — for example a `socat` TLS bridge to `gvmd.sock`.

#### Connector Mappings

1. Enter the Greenbone host in the **Location** field.
2. Enter the GMP **Username** and **Password**.
3. Optionally, set a **Minimum Severity** to limit which findings are imported.

Then configure one transport.

**For SSH:**

1. Set **Transport** to `ssh`.
2. Enter the **SSH Username** (defaults to `gmp`) and, if it is not 22, the **SSH Port**.
3. Provide either an **SSH Private Key** — with its **SSH Key Passphrase** if the key is encrypted — or an **SSH Password**. A key is preferred.
4. Enter the **SSH Host Key Fingerprint**. A server usually offers host keys of several types and there is no telling in advance which one gets negotiated, so paste **all** of them, separated by commas or spaces. `ssh-keyscan <host> | ssh-keygen -lf -` prints them for every key the host offers, and its output can be pasted as\-is. Setting **Skip SSH Host Key Check** to `true` accepts any host key instead, which is not recommended. Note that **Skip TLS Verification** does *not* do this \- it covers the TLS certificate only, so that routinely skipping the check on gvmd's self\-signed certificate cannot quietly un\-pin your host keys.
5. Optionally set the **gvmd Socket Path** if your host permits socket forwarding but keeps the socket somewhere non\-standard. Left blank, the connector probes the usual locations.

**For TLS:**

1. Leave **Transport** blank.
2. Optionally set the **GMP Port** (defaults to 9390).
3. For gvmd's default self\-signed certificate, either provide a **CA Certificate (PEM)** to verify against, or set **Skip TLS Verification** to `true`.

Each Greenbone task becomes a Record. Findings come from the task's latest finished report — one per `<result>`. Severity is taken from the result's threat level (Greenbone's `Log`/`Debug` informational levels map to Info), with the numeric CVSS score recorded; CVE references become vulnerability ids, the NVT solution becomes the mitigation, and each result's host/port becomes an endpoint.
