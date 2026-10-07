---
title: "Running DefectDojo Behind a Forward HTTPS Proxy"
description: "Configure DefectDojo Pro on-prem to reach Jira, SonarQube, and Connectors through an outbound HTTPS proxy"
draft: false
weight: 7
audience: pro
aliases:
  - /onprem_deployment/forward_proxy/
---

If your DefectDojo Pro on-prem deployment cannot make direct outbound connections to the internet — for example, because firewall rules require all egress to go through a forward HTTPS proxy — you can configure the standard `HTTPS_PROXY`, `HTTP_PROXY`, and `NO_PROXY` environment variables.  DefectDojo will route its outbound calls through the proxy accordingly.

This applies to all of DefectDojo's outbound integrations, including:

- **Jira** — creating issues, fetching transitions, polling status, pushing comments
- **SonarQube** and other tool-side calls during scan import
- **Pro Connectors** — data pulls from cloud-hosted security tools (Snyk, Tenable, AWS Security Hub, etc.)

## Setting the proxy environment variables

On `dojo-compose-cli`–based deployments, set the proxy variables in your deployment's environment configuration before bringing up the stack:

| Variable | Purpose |
| --- | --- |
| `HTTPS_PROXY` | URL of the forward HTTPS proxy DefectDojo should use for outbound HTTPS requests, e.g. `https://proxy.internal.example.com:8443` |
| `HTTP_PROXY` | URL of the proxy for outbound HTTP requests (if different from `HTTPS_PROXY`) |
| `NO_PROXY` | Comma-separated list of extra hosts, domain suffixes and CIDR ranges that should bypass the proxy, such as your internal Jira or SSO hosts. The stack's own service names are already covered (see below), so list only hosts outside the stack. |

The compose bundle passes these values to every container that makes outbound calls through its `x-proxy-vars` (`proxyenv`) block:

- **dojo** and **dojo-import-scan**: Jira, SonarQube, SSO and other web-side outbound calls
- **celeryworker** and **celerybeat**: background and scheduled tasks that make outbound calls (Jira pushes, scheduled notifications, PSIRT feed polls)
- **init**: the one-off initializer that runs before the stack starts
- **ddorch-workers**: the orchestrator workers (rules engine, scheduling, integrators and Sensei dispatch)
- **connectors** and **integrators**: cloud-tool API calls run by the Pro Connector and integrator frameworks
- **nginx**, **ddorch**, **mcp-server**, **webhook-gateway** and **sensei-engine**: added in 3.4.100, so any outbound call they make goes through the proxy (for the Sensei engine, GitHub and the LLM provider), while their calls to other containers stay direct

PSIRT feed fetches honour `HTTPS_PROXY`, `HTTP_PROXY` and `NO_PROXY` from 3.4.100. Earlier releases fetched feeds directly even with a proxy configured.

After updating the proxy variables, restart the stack so the new environment is picked up by every container.

### NO_PROXY: the internal names the bundle adds for you

The containers call each other by service name: the application calls `connectors` and `ddorch`, and the MCP server, the Sensei engine and the webhook gateway call back into `nginx` on its internal listener. If those names went to the proxy, the proxy could not resolve them and every one of those calls would fail. From 3.4.100 the compose bundle therefore always starts `NO_PROXY` with the stack's own names and network:

```text
localhost,127.0.0.1,nginx,dojo,dojo-import-scan,celerybeat,celeryworker,init,redis,postgres,connectors,integrators,integrator,ddorch,ddorch-workers,mcp-server,webhook-gateway,sensei-engine,192.168.42.0/24
```

`192.168.42.0/24` is the bundle's `dd-net` network. Whatever you set in `NO_PROXY` is appended after this list rather than replacing it, so `NO_PROXY=.corp.example.com` gives the containers the list above followed by `,.corp.example.com`.

To replace the built-in part, for example because you renamed services or changed the network, set `DD_INTERNAL_NO_PROXY` to the full list you want. Your `NO_PROXY` is still appended to it.

On releases before 3.4.100 the bundle passed `NO_PROXY` through unchanged, so a `NO_PROXY` you set there has to include the internal names above itself.

## Trusting the proxy's CA

A proxy that inspects TLS re-signs every certificate with its own CA, and the containers reject those certificates until they trust that CA. Each component reads its trusted CAs from its own place. The paths below are inside the containers; on the host, `/app/certs/` is the `certs/` directory under the install directory (`/opt/dojo/certs/` in a default install).

| Component | Where it reads extra CAs | Notes |
| --- | --- | --- |
| **dojo**, **dojo-import-scan**, **celeryworker**, **ddorch-workers**, and from 3.4.100 **celerybeat** and **init** | `/app/certs/private/dojo-ca-bundle.crt` | On startup the entrypoint merges the file with the system roots and exports the result as `REQUESTS_CA_BUNDLE`, so public CAs stay trusted. From 3.4.100 PSIRT feed fetches also trust this bundle. |
| **connectors** | `/app/certs/private/connectors-ca-bundle.crt` | Appended to `CA_BUNDLES` on startup. |
| **mcp-server** | `DD_MCP_CA_BUNDLE` (default `/app/certs/orch_tls_root.ca`) | Added to the platform roots. The default is the stack's internal CA, which it needs to reach `nginx:7443`. |
| **sensei-engine** | `SENSEI_SSL_CERT_FILE` (default `/app/certs/orch_tls_root.ca`), passed to the engine as `SSL_CERT_FILE` | Added to the system roots. Keep the internal CA in any file you point it at, or its callback to `nginx:7443` fails. |
| **webhook-gateway** | `/app/certs/dojo_internal.ca`, mounted from `certs/orch_tls_root.ca` | Delivers only to the internal `nginx` listener, so it never needs the proxy's CA. |

For the application side, install the proxy's CA (one or more PEM certificates) as `dojo-ca-bundle.crt`, as described in [Trusting an internal or private CA](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/#trusting-an-internal-or-private-ca), and restart the stack. Use `connectors-ca-bundle.crt` as well when Connector traffic goes through the same proxy. On Kubernetes, see [Trusting an internal or private CA](/get_started/pro/onprem/kubernetes/installing_on_kubernetes/#trusting-an-internal-or-private-ca).

## Verifying the proxy is in use

Once the stack is restarted:

1. Trigger a known outbound call.  Pushing a test Finding to Jira, or running a Connector sync against a tool whose API you know the proxy can reach, both work well as test signals.
2. Check your proxy server's access logs to confirm DefectDojo's containers are routing traffic through it.
3. Check the relevant DefectDojo container logs — `dojo` for synchronous calls (Jira push from the UI, SonarQube import), `celeryworker` for async calls (Jira-related background tasks) — for any TLS or network errors that would indicate the proxy is not reachable or is rejecting the request.

If outbound calls fail with TLS errors after configuring the proxy, the most common causes are:

- The proxy's TLS certificate is not trusted by the container.  If the proxy (or any upstream service) presents a certificate signed by an internal or private CA, add that CA where the failing component reads it; see [Trusting the proxy's CA](#trusting-the-proxys-ca).
- `NO_PROXY` is not configured for internal hosts, so DefectDojo is trying to reach internal services *through* the proxy and failing. From 3.4.100 the stack's own service names are covered; add your other internal hosts (Jira, SSO, SonarQube) to `NO_PROXY` so they bypass the proxy.

## Known limitation: inbound Jira webhooks

The proxy configuration documented here applies to **outbound** calls *from* DefectDojo *to* external services.  It does not help with **inbound** webhooks that external systems push *into* DefectDojo.

The most common case where this matters is Jira's bidirectional sync, which relies on Jira posting webhooks to DefectDojo's `/jira/webhook/<secret>` endpoint when issues change.  If DefectDojo is behind a firewall that prevents Jira from reaching it directly, setting `HTTPS_PROXY` will not solve that — you will need to address the inbound networking separately (a reverse proxy / load balancer with the appropriate firewall rules, an inbound NAT rule, or similar).

For Jira-specific troubleshooting, see [Troubleshooting Jira errors](/connectors/downstream/troubleshooting_jira/).
