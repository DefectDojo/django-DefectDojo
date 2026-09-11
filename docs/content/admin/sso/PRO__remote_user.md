---
title: "Remote User (Header) Authentication"
description: "Authenticate users from a trusted reverse proxy via request headers in DefectDojo Pro"
weight: 120
audience: pro
aliases:
  - /admin/sso/os__remote_user/
---

DefectDojo Pro can authenticate users from headers set by a **trusted reverse proxy** in front of DefectDojo — the pattern usually called *remote user* or *header* authentication. The proxy authenticates the user (against your IdP, Kerberos, mTLS, an access proxy, and so on) and passes the resulting identity to DefectDojo in a request header. Open-source DefectDojo does not include SSO — see [Authorized Users](/admin/user_management/os__authorized_users/) for open-source access control.

Unlike the other providers in this section, remote-user auth is **configured with environment variables, not in the Enterprise Settings UI**, and it puts no button on the login page — the proxy decides who is authenticated.

> **Security warning — only enable this behind a proxy you control that overwrites the header on every request.** DefectDojo trusts the configured header outright. If a client can reach DefectDojo directly, or the proxy forwards a client-supplied copy of the header, anyone can impersonate any user by sending that header. Always terminate the proxy in front of DefectDojo, strip the header from inbound client requests, and restrict `DD_AUTH_REMOTEUSER_TRUSTED_PROXY` to the proxy's address.

On DefectDojo Cloud, customers cannot set environment variables directly — contact DefectDojo Support to enable and configure remote-user authentication. On-premise, set the variables through your deployment (`dojo-compose-cli environment add`, Helm values, or your container environment).

## Settings

| Environment variable | Default | Purpose |
|---|---|---|
| `DD_AUTH_REMOTEUSER_ENABLED` | `False` | Master switch. When off, none of the settings below have any effect. |
| `DD_AUTH_REMOTEUSER_USERNAME_HEADER` | `REMOTE_USER` | The request-meta key carrying the username. `REMOTE_USER` is set by the web server; a custom HTTP header arrives prefixed and upper-cased — e.g. the header `X-Remote-User` is `HTTP_X_REMOTE_USER` here. |
| `DD_AUTH_REMOTEUSER_EMAIL_HEADER` | `""` | Meta key carrying the email; applied to the user when present. |
| `DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER` | `""` | Meta key carrying the first name. |
| `DD_AUTH_REMOTEUSER_LASTNAME_HEADER` | `""` | Meta key carrying the last name. |
| `DD_AUTH_REMOTEUSER_GROUPS_HEADER` | `""` | Meta key carrying a **comma-separated** list of group names. Each becomes a DefectDojo group (created on first use) with the user added as **Reader**. |
| `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP` | `True` | Remove the user from remote-provisioned groups no longer present in the header on the next request. Only groups created by this provider are affected. |
| `DD_AUTH_REMOTEUSER_TRUSTED_PROXY` | `127.0.0.1/32` | Comma-separated list of CIDR ranges. A request is honored only when its immediate peer address falls in this list; anything else is ignored. Set this to your proxy's address. |
| `DD_AUTH_REMOTEUSER_LOGIN_ONLY` | `False` | `False` — the header must be present on **every** request or the session is logged out. `True` — the header is read once to establish the session, which then behaves like a normal DefectDojo session (persistent middleware). |
| `DD_AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER` | `False` | When `True`, the header auth scheme is advertised in the `/api/v2/` OpenAPI schema. |

The email, first-name and last-name headers are re-read on each request and update the user record when they change. Group membership is applied through the same pipeline the OAuth and OIDC providers use, tagged as provider **Remote**.

## Name and email mapping

When a user first arrives, DefectDojo creates the account from the username header. If you also set the email, first-name and last-name headers, those fields are populated and kept in sync on subsequent requests. Mapping the email header is strongly recommended: DefectDojo uses the email address for notifications.

## Groups and default access

If you set `DD_AUTH_REMOTEUSER_GROUPS_HEADER`, the proxy can drive DefectDojo group membership: send a comma-separated list of group names, and DefectDojo creates each group on first use and adds the user as **Reader** of the group. A newly created group has no access to any Asset or Organization until a Superuser grants it a role — see [User Groups](../../user_management/create_user_group/).

A user who arrives with no groups lands with **no permissions**. To give every remote-user account a baseline, configure a **Default group** and **Default group role** on the System Settings page — see [Default access for SSO-provisioned users](/admin/sso/pro__saml/#default-access-for-sso-provisioned-users), which applies here too.

## Troubleshooting

**Nothing happens — users still see the normal login form.** `DD_AUTH_REMOTEUSER_ENABLED` is off, or the request is not arriving from a trusted proxy. Confirm the enabled flag and that `DD_AUTH_REMOTEUSER_TRUSTED_PROXY` contains the proxy's actual peer address (the `REMOTE_ADDR` DefectDojo sees).

**The username header is set but ignored.** The configured header name does not match the meta key DefectDojo receives. A custom HTTP header `X-Remote-User` must be configured as `HTTP_X_REMOTE_USER`. Enable `DD_AUTH_REMOTEUSER_VISIBLE_IN_SWAGGER` briefly to see the header name DefectDojo expects.

**Group memberships are not cleaned up.** `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP` only removes groups this provider created; groups assigned by hand or by another provider are left alone by design.
