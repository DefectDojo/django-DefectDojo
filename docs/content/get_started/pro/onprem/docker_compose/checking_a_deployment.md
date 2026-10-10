---
title: "Checking a Deployment with doctor and certs"
description: "Use dojo-compose-cli doctor and the certs commands to find what stops a Docker Compose deployment from starting, upgrading, or reaching a service behind an internal CA"
draft: false
weight: 6
audience: pro
---

`dojo-compose-cli` has two sets of commands for finding out what is wrong with a Docker Compose deployment. `doctor` checks the whole host and reports what would stop DefectDojo from starting or upgrading. The `certs` commands check the TLS certificates under the install directory and manage which internal CAs the containers trust.

**Which CLI version you need.** `doctor`, `certs status`, `certs add-ca` and `certs test` ship in the next `dojo-compose-cli` release after 2.1.5. Version 2.1.5 and earlier do not have them. If `dojo-compose-cli --help` does not list `doctor` and `certs`, use the manual steps linked from each section below.

Like the other commands, these need `DOJO_CLI_KEY`. Export it, then run them with `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
```

## Check the whole deployment with doctor

```bash
sudo -E dojo-compose-cli doctor
```

`doctor` only reads. It changes nothing unless you add `--fix`. It prints its findings in sections:

| Section | What it checks |
| --- | --- |
| Host | Docker and Docker Compose are installed and running, and there is room on disk for the next upgrade's images and uploaded files |
| Proxy | The Docker daemon uses the same proxy as DefectDojo. Image pulls go through the daemon, not through the CLI. |
| License | The license file is present and valid, and how many days it has left |
| Deployment | `docker-compose.yml` is in the install directory and the deployment files match the configured version |
| Permissions | `media/` belongs to user ID 1001, which the application containers run as, and the systemd unit keeps `DOJO_CLI_KEY` and the proxy out of `systemctl show` |
| Settings | Stored settings that the compose file never reads, which usually means a typo or an option a release removed |
| Services | Each container is running, and whether Docker has had to restart it |
| Database | The database is reachable |
| Certificates | The same checks as [`certs status`](#check-the-certificates) |
| Backups | How old the newest backup is |
| Versions | Whether a newer CLI or DefectDojo release is available, and which releases with upgrade notes an upgrade would cross |

The Versions section looks up releases in the registry. It is skipped when you pass `--offline`, and always skipped in air-gapped mode.

Each finding is OK, a warning, or a failure. A warning will cause trouble later, for example a license that expires soon or a backup that is weeks old. A failure stops the application or an upgrade now. The run ends with `Everything checked out.` when nothing needs attention, or with a count of the warnings when there are no failures.

`doctor` exits non-zero when any check fails. Add `--strict` to make warnings exit non-zero too, which is useful in a script or a scheduled check:

```bash
sudo -E dojo-compose-cli doctor --strict
```

Run `doctor` before an upgrade. If you contact support, include its output along with the bundle from `dojo-compose-cli diagnostics collect`.

### Let doctor fix ownership and the systemd unit

```bash
sudo -E dojo-compose-cli doctor --fix
```

With `--fix`, and only when run as root, `doctor` makes two changes before it runs the checks:

- It gives `media/` back to user ID 1001, recursively, and keeps the directory's group. Uploads fail in confusing ways when the containers cannot write there, which often happens after files were copied in as root.
- It moves `DOJO_CLI_KEY` and the proxy settings out of the systemd unit's `Environment=` lines and into the unit's root-only environment file, so `systemctl show` no longer prints them. If the unit sets values the CLI cannot carry over exactly, it leaves the unit unchanged and says so.

The fixes are reported under `Fix: bind-mounted directories`, followed by the normal checks. Without root, `--fix` changes nothing and exits with an error.

## Check the certificates

```bash
sudo -E dojo-compose-cli certs status
```

`certs status` reads every certificate and key under `certs/` in the install directory (`/opt/dojo/certs/` in a default install) and reports what would break:

- The certificate nginx serves to browsers, `certs/dojo.crt` and `certs/dojo.key`. It fails when a file is missing or unreadable, or when the key does not match the certificate, because nginx will not start. It warns when the certificate has expired or expires within 30 days, when it is still the placeholder every install ships with, and when it does not cover the host in `DD_SITE_URL`.
- The internal service certificates that ship with the deployment files.
- The two CA bundles under `certs/private/`, described in [Trusting an internal or private CA](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/#trusting-an-internal-or-private-ca). A bundle that is present but cannot be parsed is a failure. It warns when a bundle is not world-readable, and when the application bundle holds only private CAs on a DefectDojo version older than 3.4.0, where that bundle replaces the public roots instead of adding to them.
- After an upgrade, a CA bundle that is now empty although the previous install directory still has certificates in it. The warning gives the `cp` command that restores it.

`certs status` exits non-zero on failures only. Add `--strict` to exit non-zero on warnings too. When there is nothing to report it prints `Certificates are in order.`

You do not always have to run it yourself. `app start`, `app restart` and `app upgrade` run the same checks first and stop on a failure, and every CLI command prints a warning when a certificate under `certs/` has expired or is about to.

## Trust an internal CA with certs add-ca

```bash
sudo -E dojo-compose-cli certs add-ca --restart my-internal-ca.pem
```

`certs add-ca` adds the CA certificates in one or more PEM files to both bundles under `certs/private/`:

- `dojo-ca-bundle.crt`, which the application uses for the services it calls itself: SSO providers, Jira, notifications and enrichment feeds.
- `connectors-ca-bundle.crt`, which the connectors service uses for the tools it reaches.

It rebuilds the application bundle with the host's public root CAs included, so trusting an internal CA never removes trust in public ones. Certificates already in a bundle are skipped, so running it twice is safe. It warns about a certificate in your files that has expired or expires soon, or that is neither a CA certificate nor self-signed, since such a certificate makes no server trusted.

| Option | Effect |
| --- | --- |
| `--app-only` | Update only `dojo-ca-bundle.crt` |
| `--connectors-only` | Update only `connectors-ca-bundle.crt` |
| `--restart` | Restart the application afterwards so the containers read the new bundles |

`--app-only` and `--connectors-only` cannot be combined. Give neither to update both bundles.

Put the options before the file names. The CLI stops reading options at the first file name, so `certs add-ca ca.pem --restart` is refused with a message showing the right order.

The containers read the bundles only when they start. Without `--restart`, run `sudo -E dojo-compose-cli app restart` before you test.

With an older CLI, install the bundle by hand as described in [Trusting an internal or private CA](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/#trusting-an-internal-or-private-ca). On a DefectDojo version older than 3.4.0, include the public root CAs in that file as well.

## Test an outbound connection with certs test

```bash
sudo -E dojo-compose-cli certs test https://sso.example.internal/
```

`certs test` makes an HTTPS request from inside the `dojo` container, using the CA bundle the application actually loaded. It shows what SSO, Jira or an enrichment feed sees. Running `curl` on the host proves nothing about the containers, because the host has its own trust store.

The application must be running. Give exactly one `https://` or `http://` URL. The output is one line with the result, then the trust store that was used:

- `OK` followed by the HTTP status code means the TLS handshake succeeded. Any status counts here, even a 404: the test is about trust, not about the page.
- `FAILED` followed by the error type and message means the request did not complete. A certificate problem shows up as an `SSLError` that mentions `CERTIFICATE_VERIFY_FAILED`. The command exits non-zero.
- The `trust store:` line names the bundle the request trusted. If it says no private CA bundle is loaded, `certs/private/dojo-ca-bundle.crt` is empty or the containers have not been restarted since you added it.

For a tool reached through a Connector, add `--connectors` before the URL:

```bash
sudo -E dojo-compose-cli certs test --connectors https://scanner.example.internal/
```

This tests with the trust the connectors container has instead: the public roots, the files in `DD_CA_BUNDLES`, and `certs/private/connectors-ca-bundle.crt`. The `trust store:` line lists which of those files it found.

## Other certs commands

The same release adds two commands for the certificate nginx serves to browsers. Both back up the current pair under `certs/backup/` first and reload nginx without a restart when the application is running.

| Command | What it does |
| --- | --- |
| `certs install --cert <file> --key <file>` | Checks and installs your certificate and key. Add `--chain <file>` when the intermediates are in a separate file, and `--force` to install a certificate that has already expired. If nginx rejects the new files, the previous pair is put back. |
| `certs self-signed` | Generates a self-signed certificate for the host in `DD_SITE_URL` and `localhost`, valid for 825 days. Add `--hostname <name>` once per name to choose the names yourself. Browsers still warn about it, so replace it with a certificate from your CA when you have one. |

With an older CLI, replace the certificate by hand as described in [Replace the TLS certificate](/get_started/pro/onprem/docker_compose/installing_on_docker_compose/#replace-the-tls-certificate).

## Questions or support

If `doctor` reports a failure you cannot resolve, send its output and a bundle from `sudo -E dojo-compose-cli diagnostics collect` to [support@defectdojo.com](mailto:support@defectdojo.com).
