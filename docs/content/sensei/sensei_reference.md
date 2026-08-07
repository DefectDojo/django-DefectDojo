---
title: "Sensei Reference"
description: "Statuses, row actions, quotas, and troubleshooting"
draft: false
audience: pro
weight: 4
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Sensei is a DefectDojo Pro-only feature and is currently in BETA.</span>

A quick reference for the statuses, actions, and limits you'll encounter while using Sensei.

## Repository statuses

The status shown for an onboarded repository on the Sensei hub:

| Status | Meaning |
|--------|---------|
| **Active** | Onboarded and ready to scan. |
| **Pull Request Open** | Sensei has an open pull request against the repository. |
| **Pull Request Closed** | A Sensei pull request was closed. |
| **Error** | The last operation failed: check Scan Activity for the root cause. |
| **Not Configured** | The repository is connected but not yet configured. |

## Candidate and fix statuses

Auto-fix candidates and fix records move through these states:

| Status | Meaning |
|--------|---------|
| **Candidate** | Staged by a scan's auto-fix criteria. Nothing runs until you approve. |
| **In Progress** | Approved: Sensei is generating the fix and will open a pull request. |
| **PR Open** | A fix pull request is open; the badge links to it. |
| **Failed** | The fix could not be completed; it stays listed so it doesn't disappear silently. |

## Repository row actions

Each onboarded repository has a row-actions menu on the Sensei hub:

![Repository row actions](images/repo_row_menu.png)

- **Scan now:** start an on-demand scan (opens the branch picker).
- **Scan history:** view this repository's past scans.
- **Configure:** reopen the configuration form (PR reporting, automated fixes, product linkage).
- **Re-stage candidates:** re-evaluate the repository's findings against the auto-fix criteria and stage fresh candidates.
- **Delete:** remove the repository from Sensei. This stops scanning it; it does not delete the underlying asset or findings.

## Quotas and metering

Sensei is metered against your DefectDojo Pro license, shown as meters at the top of the hub:

- **Fixes:** remediations applied against your prepaid limit. Approving a candidate or triggering a fix consumes from this quota; when it is exhausted, further fixes are blocked (a warning banner appears) until the limit is raised.
- **Onboarded Repositories:** repositories onboarded against your repository limit. When it is reached, onboarding new repositories is blocked.

To raise a limit, contact your DefectDojo account team.

## GitLab specifics

GitLab is supported alongside GitHub (gitlab.com and self-managed). The scan-and-fix behavior is identical; these are the GitLab-specific details:

- **Connection:** a **project or group access token** (role **Developer**, or **Maintainer** if push rules require it) with the **`api`** and **`write_repository`** scopes, not a GitHub App. See [Set up Sensei](/sensei/setup_sensei/#connect-gitlab).
- **Webhook:** each onboarded project needs a webhook to `…/sensei/gitlab/webhooks` (with the connection's secret) subscribed to **Push**, **Merge request**, and **Comment** events. Adding a webhook requires **Maintainer**/**Owner** on the project.
- **Merge requests, not pull requests:** fixes open a **merge request** against the default branch; the `/fix` comment works on merge-request notes.
- **Commit-status gate:** the PR status check is a GitLab **commit status** on the merge request's head commit: `running` while scanning, then `success` or `failed` (fail-on-new). GitLab has no *neutral* state, so a **non-gating** scan that still has findings shows a **green** status; the summary note carries the finding details.
- **Self-managed:** point the **GitLab Base URL** at your instance; DefectDojo clones and calls the API against that host.

## Bitbucket specifics

Bitbucket **Cloud** and **Server/Data Center** are supported. The scan-and-fix behavior is identical; these are the Bitbucket-specific details:

- **Connection:** **OAuth** (recommended), an Atlassian **API token** (used with your account email), or a repository/workspace **access token**. See [Set up Sensei](/sensei/setup_sensei/#connect-bitbucket). App passwords are deprecated and not supported.
- **Workspace scoping (Cloud):** API/access tokens are workspace-bound, so a **workspace** is required for Cloud; OAuth is user-context and discovers accessible workspaces automatically.
- **Webhook:** each onboarded repository needs a webhook to `…/sensei/bitbucket/webhooks` (with the connection's secret, verified via HMAC-SHA256 `X-Hub-Signature`) subscribed to **Push**, **Pull request** (created/updated/merged/declined), and **Pull request comment** events.
- **Build-status gate:** the PR status check is posted as a Bitbucket **build status** on the head commit (`INPROGRESS` → `SUCCESSFUL`/`FAILED`). Bitbucket has no *neutral* state, so a non-gating scan maps to `SUCCESSFUL` and the summary comment carries the detail. The build-status link must be a public URL, so it uses your DefectDojo host.
- **Repository names:** `workspace/repo` (Cloud) or `PROJECTKEY/repo` (Server/Data Center).
- **Server/Data Center:** set the **Base URL** to your host; DefectDojo uses the v1.0 REST API and `/scm/…` git paths.

## Azure DevOps specifics

Azure DevOps Repos are supported via a **Personal Access Token**. The scan-and-fix behavior is identical; these are the Azure-specific details:

- **Connection:** a **PAT** with the **Code (Read, Write, & Manage)** scope, plus the **organization**. Azure DevOps OAuth apps are being retired, so a PAT is the recommended credential. See [Set up Sensei](/sensei/setup_sensei/#connect-azure-devops).
- **Webhook:** Azure **Service Hooks** authenticate with HTTP **Basic** (not an HMAC) and use **one subscription per event**. Create subscriptions to `…/sensei/azure/webhooks` for **Code pushed** and **Pull request created/updated/merged**, with the connection's Basic username/password.
- **Commit-status gate:** the PR status check is posted as a Git **commit status** on the head commit.
- **Repository names:** `project/repo` (the organization is stored on the connection).
- **Azure DevOps Server:** set the **Base URL** to your on-prem collection URL.

## GitHub Enterprise Server specifics

GitHub Enterprise Server uses the **same GitHub App** model as github.com; only the host differs:

- **Connection:** because the App-manifest auto-create flow is github.com-only, create the App **manually** on your GHES host and enter its credentials plus the **Enterprise host** via **Set up manually**. See [Connect GitHub Enterprise Server](/sensei/setup_sensei/#connect-github-enterprise-server). DefectDojo derives the API (`/api/v3`) and web origins from the host.
- **Coexistence:** a github.com App connection and a GHES App connection can be configured on the same instance; each repository resolves to the connection it was onboarded through.
- **Reachability:** DefectDojo must reach the GHES API host, and GHES must reach DefectDojo's `…/sensei/webhooks` endpoint (internal hosts are fine if both sides can connect).

## Troubleshooting

- **The Sensei button on a finding says "Configure Product."** The finding's product isn't onboarded. Click it to onboard a repository for that product, then return to the finding.
- **A fix shows "Failed" in Auto-fix Candidates or Scan Activity.** Open **Scan Activity** and check the **Root Cause** / **Details** for that run. Failed fixes remain listed so they don't disappear before producing a PR; you can re-stage and retry.
- **A repository isn't listed when onboarding.** Only repositories the connection can access are shown. On **GitHub**, confirm the App is installed on the correct organization and its repository access includes the repository. On **GitLab**, confirm the access token's scope covers the project. On **Bitbucket Cloud**, confirm the **workspace** is set (tokens are workspace-scoped). On **Azure DevOps**, confirm the PAT's organization matches and its **Code** scope is granted.
- **Scans or fixes never start after a webhook.** Confirm the repository's webhook points at the provider's receiver (`…/sensei/{gitlab,bitbucket,azure}/webhooks`, or `…/sensei/webhooks` for GitHub) with the correct secret/credentials, and subscribes to push + pull-request (+ comment) events. The provider's **recent deliveries** should show `HTTP 200`. Webhook-driven runs fire only for repositories onboarded in **hosted** mode; a push to a non-default branch is scanned via its pull request, not on its own.
- **Nothing is happening after a scan.** Check that automated fixes are enabled (and your severity/risk thresholds match findings) on the repository's configuration, and that your **Fixes** quota isn't exhausted.

> **🔎 Still in BETA:** Sensei is evolving quickly. If behavior doesn't match this guide, check the [Pro changelog](/releases/pro/changelog/) for recent changes.
