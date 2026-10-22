---
title: "Service Users"
description: "API-only users for pipelines, scanners and other automation"
audience: pro
weight: 2
---

A service user is a DefectDojo user meant for automation: a CI/CD pipeline, a scanner, a Kubernetes workload. It has no email address and no password, it can never sign in to the UI, and it holds one API token that is shown once, when it is created or regenerated. Everything else about it works like any other user: it is authorized through a global role, Asset and Organization memberships, groups and configuration permissions.

Service users are kept apart from people. They are managed on their own pages, not on the Users pages or in the Members tabs of Assets, Organizations and groups. They are not offered when work is assigned or a reviewer is chosen, they are not managed by SCIM, SSO or LDAP, they are never added to the default group, they receive no email, and they do not count toward the licensed user total.

## Turn on Service Users

Service Users is an opt-in feature. A superuser turns it on under **Settings > Feature Flags > Service Users**.

Turning the feature off stops every service user token from authenticating, immediately, until it is turned back on. Any pipeline using one fails while the feature is off, so the Feature Flags page asks for confirmation before turning it off. The service users themselves and their settings are kept.

## Create a service user

Open **Settings > Users & Permissions > Service Users** and select **New Service User**. Creating one needs the **Service User Add** permission, which the global Owner and Maintainer roles carry.

* **Service User Label**: the name shown wherever a user is named, for example "GitLab payments pipeline". It appears as the label followed by the username, such as "GitLab payments pipeline (svc-gitlab-payments)".
* **Username**: filled in from the label. It always starts with `svc-`, uses lowercase letters, digits, dots, dashes and underscores, and cannot be changed later. The `svc-` prefix is reserved: no person can be given a username that starts with it.
* **Description**: what the service user is for.
* **Token Expires**: 30, 60, 90 or 180 days, or No Expiration. 90 days is selected by default.
* **Global Role**: optional. A role applied everywhere, like a global role on any user. Only a superuser or a global Owner can assign one, and a service user can never be a superuser.

When you submit, DefectDojo shows the token once. Copy it into the secret store your pipeline reads from (a protected CI/CD variable, a Kubernetes Secret). DefectDojo stores only a hash of the token, so it cannot show it again. If it is lost, regenerate it.

Closing the token dialog opens the service user's page, where its access is added.

## Give a service user access

A new service user has no access until it is given some, the same as a new user. Its page shows its details and token, and manages its access:

* **Organizations** and **Assets**: select **Add Access**, pick one or more, and choose a role. **API Importer** is the role made for uploading scans: it can import and reimport, and read the Assets, Engagements, Tests and Findings it is a member of. The list offers only the Assets or Organizations where you can manage members, and adding an Owner role needs the right to add owners there.
* **Groups**: add the service user to a group, the same as a user.
* **Configuration Permissions**: shown to superusers, the same as on a user's page.

One service user per pipeline or scanner, with the API Importer role on the Assets it uploads to, keeps each token's reach small and shows in the history which integration made each change.

## Use the token

Send the token in the `Authorization` header with the `Token` keyword, the same way as any API token:

    Authorization: Token ddsu_<token>

For example, to import a scan into an Asset the service user is a member of:

    curl -X POST "https://defectdojo.example.com/api/v2/import-scan/" \
      -H "Authorization: Token ddsu_<token>" \
      -F "scan_type=Trivy Scan" -F "product_name=Payments API" \
      -F "engagement_name=CI" -F "auto_create_context=true" \
      -F "file=@trivy.json"

A request outside the service user's access is refused the same way as for any user.

### Exchange the token for a short-lived access token (OAuth 2.0)

A client that supports the OAuth 2.0 client credentials grant can exchange the token for an access token that is valid for one hour, so the long-lived token is not sent with every request:

    curl -X POST "https://defectdojo.example.com/api/v2/oauth/token/" \
      -d grant_type=client_credentials \
      -d client_id=svc-gitlab-payments \
      -d client_secret=ddsu_<token>

The response carries `access_token`, `token_type` (`Bearer`) and `expires_in` (seconds). Send the access token as `Authorization: Bearer <access_token>`, and request a new one when it expires. Disabling the service user, or turning the feature off, stops its access tokens at once. Regenerating its token does not end access tokens already issued; they expire within the hour.

## Manage service users

Select a service user's name to open its page. Each row's menu on the Service Users page, and the gear menu on its page, offer:

* **View Service User**: the service user's page.
* **Edit Service User**: change the label, description, global role and token expiry. The username cannot be changed.
* **Regenerate Token**: issue a new token and show it once. The current token stops working immediately. OAuth access tokens already issued from it keep working until they expire, within the hour.
* **Disable Service User** and **Enable Service User**: a disabled service user keeps its token, but the token is refused until the service user is enabled again.
* **Delete Service User**: remove the service user, its token, its memberships, its groups and its global role. A service user that is recorded on findings or other records, for example as the reporter of findings it imported, cannot be deleted: disable it instead.

Editing, regenerating or deleting a service user needs the right to grant every kind of access it holds. For example, a user who cannot assign global roles cannot change a service user that has one, and a user who cannot add owners to an Asset cannot change a service user that is an Owner there. Superusers can always manage service users.

The list shows each token's first characters, when it expires, when it was last used and its status: Active, Expiring Soon (within 14 days), Expired or Disabled.

A service user authenticates only with its own token. It is never given a regular API token, so features that create one for the person asking, such as generating a token for a Sensei workflow, refuse a service user. The Users page's **Force Token Reset** and **Reset API Tokens** never rotate a service user's token: rotate it from the Service Users page or the API, where the new token is shown.

## Automate with the API

The same operations are available at `/api/v2/service_users/` with an API token, for holders of the Service User permissions:

| Operation | Request |
| --- | --- |
| List | `GET /api/v2/service_users/` |
| Create | `POST /api/v2/service_users/` with `label`, `username`, `expires_in_days` (30, 60, 90, 180 or `null`), and optional `description` and `global_role_id`. The response includes `token`, once. |
| Change | `PATCH /api/v2/service_users/<id>/` with any of `label`, `description`, `expires_in_days`, `is_active`, `global_role_id` |
| Regenerate the token | `POST /api/v2/service_users/<id>/regenerate_token/`. The response includes the new `token`, once. |
| Delete | `DELETE /api/v2/service_users/<id>/` |

Give a service user access with the same endpoints used for any user, with its `user_id` from the service user's record: `POST /api/v2/product_members/`, `POST /api/v2/product_type_members/` and `POST /api/v2/dojo_group_members/`. Those endpoints list service users' memberships along with everyone else's.

A token can also be revoked by its value with `POST /api/v2/api-tokens/revoke/`, the same endpoint used for user tokens.
