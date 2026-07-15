---
title: "Running DefectDojo Behind a Forward HTTPS Proxy"
description: "Configure DefectDojo Pro on-prem to reach Jira, SonarQube, and Connectors through an outbound HTTPS proxy"
audience: pro
weight: 5
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
| `NO_PROXY` | Comma-separated list of hosts and CIDR ranges that should bypass the proxy.  Typically includes internal hostnames, the Docker bridge network, and `localhost`/`127.0.0.1`. |

`dojo-compose-cli` propagates these values to the containers it manages via its `proxyenv` mechanism.  Setting `HTTPS_PROXY` once at the deployment level reaches the containers that need it:

- the **uwsgi** container — Jira, SonarQube, and other web-side outbound calls
- the **celeryworker** containers — async background tasks that make outbound calls (Jira pushes, scheduled notifications, etc.)
- the **Connector** containers — cloud-tool API calls run by the Pro Connector framework

After updating the proxy variables, restart the stack so the new environment is picked up by every container.

## Verifying the proxy is in use

Once the stack is restarted:

1. Trigger a known outbound call.  Pushing a test Finding to Jira, or running a Connector sync against a tool whose API you know the proxy can reach, both work well as test signals.
2. Check your proxy server's access logs to confirm DefectDojo's containers are routing traffic through it.
3. Check the relevant DefectDojo container logs — `uwsgi` for synchronous calls (Jira push from the UI, SonarQube import), `celeryworker` for async calls (Jira-related background tasks) — for any TLS or network errors that would indicate the proxy is not reachable or is rejecting the request.

If outbound calls fail with TLS errors after configuring the proxy, the most common causes are:

- The proxy's TLS certificate is not trusted by the container.  You may need to inject a CA bundle into the containers depending on your proxy's TLS configuration.
- `NO_PROXY` is not configured for internal hosts, so DefectDojo is trying to reach internal services *through* the proxy and failing.

## Known limitation: inbound Jira webhooks

The proxy configuration documented here applies to **outbound** calls *from* DefectDojo *to* external services.  It does not help with **inbound** webhooks that external systems push *into* DefectDojo.

The most common case where this matters is Jira's bidirectional sync, which relies on Jira posting webhooks to DefectDojo's `/jira/webhook/<secret>` endpoint when issues change.  If DefectDojo is behind a firewall that prevents Jira from reaching it directly, setting `HTTPS_PROXY` will not solve that — you will need to address the inbound networking separately (a reverse proxy / load balancer with the appropriate firewall rules, an inbound NAT rule, or similar).

For Jira-specific troubleshooting, see [Troubleshooting Jira errors](/connections/downstream/troubleshooting_jira/).
