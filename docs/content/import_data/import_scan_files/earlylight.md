---
title: "Scan with Early Light"
description: "Find newly disclosed vulnerabilities with DefectDojo's open source Early Light scanner, then import the results"
weight: 5
---

[Early Light](https://github.com/DefectDojo/earlylight) is DefectDojo's free, open source scanner for emerging vulnerabilities. Each newly disclosed vulnerability it covers is a detector in one binary, `earlylight`. A detector proves its verdict from the files themselves, such as the error table compiled into a library, a Linux vendor's backport data or a certificate's key, rather than trusting a version string.

Early Light runs on Linux, macOS and Windows as a single static binary. It runs on your own machine or CI runner, has no telemetry or account, and sends nothing to DefectDojo. You import its report into DefectDojo Pro or the Open Source edition like any other scan.

## Detectors

New releases add detectors as vulnerabilities are disclosed. Run `earlylight detectors` to list the ones in the release you have. At v0.5.0 there are four:

| Detector | Finds | Scan modes |
| --- | --- | --- |
| `brotli` | Brotli decoders vulnerable to CVE-2026-111497 ("Node2Shell"): the system `libbrotlidec` and the copies bundled into Node.js, .NET, Bun, Electron, Envoy, Python wheels and other software, plus the Node.js, .NET and Bun versions a source tree pins | `fs`, `image`, `repo`, `fix` |
| `emudhra` | Trust in the eMudhra intermediate CA keys compromised in October 2026: trust stores, bundles, keystores and binaries that still trust them, Go binaries built without Go's blocklist (CVE-2026-111943), and servers presenting certificates those keys signed | `fs`, `image`, `host` |
| `php2shell` | PHP runtimes vulnerable to CVE-2026-109618 and CVE-2026-109619 ("PHP2Shell"). A PHP installed by a package manager is judged by its vendor's backport data, not by the version it reports | `fs`, `image`, `repo`, `fix` |
| `sshole` | The OpenSSH password authentication bypass on musl libc ("\*sshole"), fixed in OpenSSH 10.6p2 and in Alpine's openssh packages of November 5, 2026. It checks each sshd's C library, release and package database, then whether its `sshd_config` and account files make the bypass reachable, and reports the accounts. It has no CVE yet | `fs`, `image`, `host`, `repo`, `fix` |

Each release also publishes `detectors.json` (the output of `earlylight detectors --format json`), which lists every detector's CVEs, advisories, scan modes and finding kinds.

## Install

On Linux and macOS, use one of:

```bash
curl -fsSL https://raw.githubusercontent.com/DefectDojo/earlylight/main/install.sh | sh
brew install defectdojo/tap/earlylight
go install github.com/DefectDojo/earlylight/cmd/earlylight@latest
```

`install.sh` checks the binary against the release's `checksums.txt`, and also verifies that file's Sigstore signature when `cosign` is installed. It installs the latest release to `/usr/local/bin`, or to `~/.local/bin` when that isn't writable. Set `EARLYLIGHT_VERSION` (for example `v0.5.0`) to pin a release and `EARLYLIGHT_BIN_DIR` to choose the directory.

On Windows, download `earlylight` for your architecture from the [releases page](https://github.com/DefectDojo/earlylight/releases), which has binaries for every platform, or use `go install`.

Check the install with `earlylight version`.

A container image is also available, for CI systems that run each step in a container and for Kubernetes jobs. Without `--output`, the report is written to standard output, so redirect it to a file:

```bash
docker run --rm ghcr.io/defectdojo/earlylight \
  scan image --format json php:8.3-fpm > earlylight.json
```

The image runs as a non-root user. To write the report into a mounted directory with `--output` instead, also pass `--user "$(id -u)"` so it can write there.

## Run a scan

```bash
earlylight scan <mode> [flags] TARGET...
```

| Mode | Scans | Example |
| --- | --- | --- |
| `fs` | Directories or files on this machine. Use `/` for the whole system | `sudo earlylight scan fs /` |
| `image` | Container images, pulled from their registry | `earlylight scan image php:8.3-fpm node:24-slim` |
| `repo` | A source tree: the images its Dockerfiles, Compose files, Kubernetes manifests, Helm values and CI files build on and deploy, and the runtimes and packages it pins | `earlylight scan repo .` |
| `host` | Live servers: TLS for `emudhra`, SSH for `sshole` (`host`, `host:port` or a URL) | `earlylight scan host example.com` |

Use `repo`, not `fs`, for a source tree. `fs` reads installed software and doesn't check the image references and version pins in a source tree, so it reports a repository that pins vulnerable releases as clean.

Every detector that supports the mode runs, unless you name some with `--detector`, for example `--detector brotli,php2shell`.

**Put flags before the targets.** Everything after the first target is read as another target, so `earlylight scan image node:24-slim --format json` tries to scan images named `node:24-slim`, `--format` and `json`, and writes no JSON report.

Useful flags:

- `--format text|json|sarif` and `--output FILE`: the report format and where to write it. DefectDojo imports `json` and `sarif`.
- `--exit-zero`: exit 0 even when something is vulnerable, for pipelines that import the report rather than fail the step. Errors still exit 2.
- `--platform OS/ARCH|all`: which platform of a multi-platform image to scan. The default is `linux/amd64`.
- `--show-cleared`: also list findings Early Light proved fixed or not in use.
- `--public-registries-only`: for `repo` scans of code you don't control, such as pull requests from forks. Early Light then contacts only public registries.

### Scanning images

`scan image` downloads the image from its registry itself; it does not go through the local Docker daemon. It uses the credentials saved by `docker login`, so log in before scanning private images, or if Docker Hub's anonymous pull limit stops a scan with `TOOMANYREQUESTS`.

To scan an image that exists only on your machine, save it to a file first:

```bash
docker save -o app.tar myorg/app:dev
earlylight scan image docker-archive:app.tar
```

### Fixing a source tree

For the detectors that list `fix` among their modes, `earlylight fix` moves the pins and image references a `repo` scan finds to their fixed releases. Preview the changes with `--dry-run`, which prints each change followed by its diff, and exits 1 when there is something to fix:

```bash
earlylight fix --dry-run .
```

```text
would fix  .nvmrc:1  Changes Node.js 24.10.0 to 24.22.1 on line 1 of .nvmrc, the fixed release of the same line for CVE-2026-111497 (the bundled Brotli decoder).
           @@ .nvmrc line 1 @@
           - 24.10.0
           + 24.22.1
```

## Verdicts and exit status

Early Light gives every finding one of five verdicts. A finding is cleared (`fixed`, `inactive` or `managed`) only with a reason; when a detector can't give one, the verdict is `unknown`.

| Verdict | Meaning | Imported into DefectDojo |
| --- | --- | --- |
| `vulnerable` | Proven exposed | Yes |
| `unknown` | The evidence doesn't settle it. The reason says what to check | Yes |
| `fixed` | Proven to have the fix | No |
| `inactive` | Present, but provably not used | No |
| `managed` | Another layer decides, such as the OS keychain or a browser's blocklist | No |

The exit status is:

- `1` when something is vulnerable, even if another target failed
- `2` on an error, for example a target that couldn't be scanned, when nothing is vulnerable. With `--exit-zero`, an error always exits 2
- `3` when nothing is vulnerable but something is unknown
- `0` otherwise

A target that fails, for example an image the registry refuses, is still listed in the report, with an `error` field in JSON. Since exit status 1 can hide a failed target, check each target's `error` field, so an empty or partial Test isn't mistaken for a clean result.

## Import into DefectDojo

Early Light writes two report formats that DefectDojo can import:

| | JSON (`--format json`) | SARIF (`--format sarif`) |
| --- | --- | --- |
| Scan Type | **Early Light Scan** | **SARIF** |
| Title | `<detector>/<kind>: <message>` | The message and the reason |
| `unknown` findings | Tagged `needs-review`, with the reason at the top of the description | Not tagged. The title starts with `Could not be settled:`, and the severity is the kind's score, so most import as Critical |
| Component name and version | Set when the finding names one, for example `php` `8.3.0` or `node` `24.10.0` | Not set |
| CVEs | Only the finding's own CVEs. eMudhra trust-store findings have none | Every finding gets its detector's CVEs |
| Matching on reimport | By detector, kind, target and path, so a Finding stays the same Finding when, for example, the installed version changes | By every fact Early Light reports, including versions, so a version change closes the Finding and opens a new one |

Use JSON with the **Early Light Scan** type when your DefectDojo version lists it under Scan Type, and SARIF otherwise. The [Early Light parser](/supported_tools/parsers/file/earlylight/) page describes how each JSON field is mapped and how severity is chosen.

### From the UI

1. Run the scan with a JSON report:

    ```bash
    earlylight scan image --format json --output earlylight.json php:8.3-fpm
    ```

2. Open the Engagement that should hold the results and import a scan. See [Import Scan form](/import_data/import_scan_files/os__import_scan_ui/) (Open Source) or [Import Scan form](/import_data/import_scan_files/pro__import_scan_ui/) (Pro).
3. Set **Scan Type** to **Early Light Scan**, choose `earlylight.json`, and submit.

A report that covers several targets, such as several images scanned in one command, imports into one Test with every target's Findings. A report with no vulnerable or unknown findings creates an empty Test.

### From the API

Use the `/api/v2/reimport-scan/` endpoint so each run updates the same Test:

```bash
earlylight scan image --exit-zero --format json --output earlylight.json myorg/app:prod

curl -X POST "https://defectdojo.example.com/api/v2/reimport-scan/" \
  -H "Authorization: Token $DEFECTDOJO_API_TOKEN" \
  -F "file=@earlylight.json" \
  -F "scan_type=Early Light Scan" \
  -F "product_type_name=Platform" \
  -F "product_name=app" \
  -F "engagement_name=Early Light" \
  -F "test_title=myorg/app:prod" \
  -F "auto_create_context=true"
```

`product_type_name` and `product_name` are the Organization and the Asset. With `auto_create_context`, any of them that don't exist yet are created.

On each reimport, Findings that are still reported are left as they are, Findings missing from the new report are closed, and a closed Finding that is reported again is reopened. Give each image or source tree its own `test_title`, so that one target's scan doesn't close another target's Findings. See [Import from API](/import_data/import_scan_files/api_pipeline_modelling/) for the other parameters.

## Run Early Light in GitHub Actions

Install Early Light, write a JSON report, and import it with the [DefectDojo action](/import_data/import_scan_files/github_actions/):

```yaml
name: Early Light
on:
  push:
    branches: [main]
  schedule:
    - cron: "0 6 * * *"

permissions:
  contents: read

jobs:
  earlylight:
    runs-on: ubuntu-latest
    env:
      EARLYLIGHT_VERSION: v0.5.0
      EARLYLIGHT_BIN_DIR: ${{ runner.temp }}/earlylight
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - name: Scan
        run: |
          curl -fsSL "https://raw.githubusercontent.com/DefectDojo/earlylight/$EARLYLIGHT_VERSION/install.sh" | sh
          "$EARLYLIGHT_BIN_DIR/earlylight" scan repo --exit-zero --format json --output earlylight.json .
      - name: Import into DefectDojo
        uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: earlylight.json
          scan-type: Early Light Scan
          test-title: Early Light
          fail-on: critical
```

`--exit-zero` lets the import run when something is vulnerable, and the DefectDojo action's `fail-on` then decides whether the job fails. A scan error still exits 2 and stops the job.

The workflow pins Early Light to one release, so a run only picks up new detectors when you change `EARLYLIGHT_VERSION`. To scan with every new detector as soon as it ships, remove `EARLYLIGHT_VERSION` and install from `main`; the scheduled run then uses the latest release each day, at the cost of running code you haven't reviewed.

The DefectDojo action puts the results in an Engagement named after the branch, unless you set `engagement-name`. See [Where the Findings go](/import_data/import_scan_files/github_actions/#where-the-findings-go).

### With the Early Light action

The [Early Light action](https://github.com/marketplace/actions/early-light-by-defectdojo) installs a checksum-verified release, writes a SARIF report and adds a findings table to the job summary. With `upload-sarif: true` and the `security-events: write` permission, it also uploads the report to GitHub code scanning.

To import its report, use the **SARIF** scan type, and set `fail-on: never` so a vulnerable result doesn't stop the job before the import. Give the Test its own `test-title`: otherwise it is named `SARIF`, and the reimport would close the Findings of any other SARIF report imported into the same Engagement.

```yaml
    steps:
      - uses: actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1 # v7.0.1
      - uses: DefectDojo/earlylight@v0
        with:
          mode: repo            # fs, image, repo or host
          target: .
          fail-on: never
      - uses: DefectDojo/defectdojo-action@v1
        with:
          defectdojo-url: https://defectdojo.example.com
          api-token: ${{ secrets.DEFECTDOJO_API_TOKEN }}
          file: earlylight.sarif
          scan-type: SARIF
          test-title: Early Light
          fail-on: critical
```

The Early Light action runs on Linux and macOS runners.

## Run Early Light from an AI agent

An AI coding agent that can run shell commands, such as Claude Code, can run Early Light and explain the results. Paste this prompt into the agent and replace the text in angle brackets with what to scan:

```text
Use Early Light (https://github.com/DefectDojo/earlylight) to check
<this repository | the image myorg/app:prod | this machine> for emerging
vulnerabilities.

1. Run `earlylight version`. If it isn't installed, ask me before
   installing it. On Linux or macOS, install it with:
   curl -fsSL \
     https://raw.githubusercontent.com/DefectDojo/earlylight/main/install.sh | sh
   Otherwise, point me to
   https://github.com/DefectDojo/earlylight/releases and stop.
2. Run `earlylight detectors` to see which vulnerabilities this release
   covers. Not every detector runs in every scan mode; the report's
   `detectors` list shows which ones ran.
3. Choose the scan mode:
   - `repo` for a source tree or checked-out repository. It checks the
     images its Dockerfiles, Compose files, Kubernetes manifests, Helm
     values and CI files use, and runtime pins such as `.nvmrc`. Don't
     use `fs` on a source tree: it doesn't check image references or
     pins, so it can report a vulnerable repository as clean.
   - `image` for container images. Images are scanned as linux/amd64;
     add `--platform all` if I deploy other platforms.
   - `fs` for an installed system or a directory of installed software.
     Ask me before using sudo.
   - `host` for a live server. Scan only hosts I have named.
4. Scan with a JSON report, written outside the directory you scan. Put
   every flag before the targets, because anything after the first
   target is read as another target:
   earlylight scan <mode> --format json --output <report path> <target>
   Exit status 1 means something is vulnerable (unknown findings may
   also be present), 3 that nothing is vulnerable but something is
   unknown, and 2 an error. Exit 1 and 3 are results, not a failed
   command.
5. Read the report. For each entry in `targets`, check for an `error`
   field first: a target with one was not scanned, so report it as not
   scanned, never as clean. Also report the count of its `skipped`
   files, and whether they look like files that matter. If an image
   fails with TOOMANYREQUESTS or an authentication error, ask me to run
   `docker login`.
6. Report every finding whose `verdict` is `vulnerable` or `unknown`,
   with its `detector`, `kind`, `path` (and `line` when present),
   `reason` and `fix`. When a finding has no `reason`, use its
   `message`. When it has no `fix`, say the report gives none rather
   than inventing one. For `unknown`, the reason says what evidence is
   missing: check it if you can, and tell me what you found. The same
   issue can appear at several paths, such as a certificate in a bundle
   and in its source file, so group related findings.
7. For a source tree, run `earlylight fix --dry-run <dir>` and show me
   the proposed changes. It exits 1 when there is something to fix. A
   finding it can't change automatically has to be fixed by hand, so
   list those separately. Don't run `earlylight fix` without `--dry-run`
   until I agree.
8. Finish with a summary: what was scanned, what is vulnerable, what is
   unknown and what to check next, and what could not be scanned.

Don't upload the report anywhere unless I ask. If I ask you to import it
into DefectDojo, use the /api/v2/reimport-scan/ endpoint with scan_type
"Early Light Scan", read the API token from the DEFECTDOJO_API_TOKEN
environment variable, and never print the token.
```

The prompt keeps the agent to the commands on this page: it asks before installing software, using `sudo`, changing files or uploading the report, and scans only the hosts you name, because a `host` scan connects to them.

## Network access

Early Light connects to the network only when a scan needs it:

| Command | Connects to |
| --- | --- |
| `install.sh` and the Early Light action | GitHub, to download the release and its checksums, and Sigstore when `cosign` is installed |
| `scan image` | The registry that hosts each image |
| `scan repo` and `fix` | The registries that host the images the source tree references. `--offline` turns this off |
| `scan host` | The hosts you name: a TLS handshake, and for `sshole` an SSH handshake that asks which login methods the server offers and never sends a password. The server logs it as a connection that didn't authenticate |
| `scan fs` | Nothing |

## Links

- [Early Light on GitHub](https://github.com/DefectDojo/earlylight)
- [Releases](https://github.com/DefectDojo/earlylight/releases)
- [Early Light parser](/supported_tools/parsers/file/earlylight/)
