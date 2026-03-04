---
title: "RemoteUser"
description: "Configure RemoteUser authentication in Open-Source DefectDojo"
weight: 19
audience: opensource
---

RemoteUser authentication is suitable when DefectDojo is deployed behind an HTTP authentication proxy. The proxy handles authentication and passes user information to DefectDojo via HTTP headers.

**Warning:** The proxy must be configured to strip any attacker-supplied headers matching the `DD_AUTH_REMOTEUSER_*` variable names before forwarding requests to DefectDojo, to prevent header spoofing. See the [Django documentation](https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#configuration) for details.

## Configuration

Set the following as environment variables, or without the `DD_` prefix in your `local_settings.py` file (see [Configuration](/get_started/open_source/configuration/)):

| Variable | Required | Description |
|---|---|---|
| `DD_AUTH_REMOTEUSER_ENABLED` | Yes | Set to `True` to enable RemoteUser authentication |
| `DD_AUTH_REMOTEUSER_USERNAME_HEADER` | Yes | Header containing the username |
| `DD_AUTH_REMOTEUSER_TRUSTED_PROXY` | Yes | Comma-separated list of trusted proxy IPs or CIDR ranges |
| `DD_AUTH_REMOTEUSER_EMAIL_HEADER` | No | Header containing the user's email address |
| `DD_AUTH_REMOTEUSER_FIRSTNAME_HEADER` | No | Header containing the user's first name |
| `DD_AUTH_REMOTEUSER_LASTNAME_HEADER` | No | Header containing the user's last name |
| `DD_AUTH_REMOTEUSER_GROUPS_HEADER` | No | Header containing a comma-separated list of groups; the user will be assigned to these groups, and any missing groups will be created |
| `DD_AUTH_REMOTEUSER_GROUPS_CLEANUP` | No | When `True`, removes the user from any groups not present in the current request's group header |
| `DD_AUTH_REMOTEUSER_LOGIN_ONLY` | No | See [Django documentation](https://docs.djangoproject.com/en/3.2/howto/auth-remote-user/#using-remote-user-on-login-pages-only) |

## User Permissions

When a new user is created via RemoteUser (or any other SSO method), they are assigned only default permissions and cannot add, edit, or delete anything in DefectDojo.

To grant permissions to new users automatically, configure the following in **System Settings**:

- **Default group** — assign new users to a specific group on creation
- **Default group role** — set the role new users receive within that group

For group-based access via the `DD_AUTH_REMOTEUSER_GROUPS_HEADER`, permissions are inherited from the groups the user belongs to. See [User Permissions](../../user_management/set_user_permissions/) and [User Groups](../../user_management/create_user_group/) for more information.
