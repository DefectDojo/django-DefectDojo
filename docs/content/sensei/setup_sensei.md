---
title: "Set Up Sensei"
description: "Connect a GitHub App or GitLab, and onboard a repository for hosted scanning"
draft: false
audience: pro
weight: 2
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Sensei is a DefectDojo Pro-only feature and is currently in BETA.</span>

Setting up Sensei has two parts: **connect a source-control provider** (a **GitHub App**, or **GitLab** with an access token), then **onboard the repositories** you want to scan. You need a global **Maintainer** or **Owner** role to do this.

Onboarding, configuration, scanning, and fixing are the same for both providers; only the initial connection differs. This page covers [connecting a GitHub App](#connect-a-github-app) and [connecting GitLab](#connect-gitlab); the [Select repositories](#select-repositories) step onward is shared.

## Connections

A **connection** is one configured source-control identity (a GitHub App installation group). You onboard repositories from a connection, and manage or disconnect it, from the **Connections** page (the **Connections** button on the Sensei hub).

![Sensei Connections](images/connections.png)

The table lists each connection's provider, label, identity, number of installs, number of onboarded repos, and creation date. Use the row actions to manage the app on GitHub, add repositories from that connection, or disconnect it.

> **⚠️ Disconnecting is destructive:** disconnecting a connection removes it **and every repository onboarded through it**. This cannot be undone.

## Connect a GitHub App

Sensei runs entirely through a GitHub App. Install it on your org/account and DefectDojo uses short-lived tokens to open PRs, scan, and apply fixes. Nothing to paste, nothing to rotate.

From the Sensei hub, choose **Add Repositories** (or **Connect** on the Connections page) to open **Set Up Sensei**.

### Step 1: Create the App

Enter the **organization** that owns the repositories you want to scan (leave blank to create the App on your personal account), then click **Create GitHub App**. GitHub pre-fills the app name, URLs, and permissions; you just review and confirm.

![Create the GitHub App](images/setup_create_app.png)

GitHub opens a confirmation page. Click **Create GitHub App for `<org>`** to register the app under that organization.

![Confirm app creation on GitHub](images/github_create_app.png)

> **🔑 Tip:** Create the App on the same organization that owns the repositories you plan to scan. The App owner is set at creation time.

### Step 2: Install the App

Back in DefectDojo, the app shows as *configured*. Click **Install on GitHub** to install it on your organization.

![App created, install it](images/setup_install_app.png)

On GitHub, confirm the installation location (your organization), choose **All repositories** or **Only select repositories**, and review the requested permissions. Sensei needs read access to actions, issues, and metadata, and read/write access to checks, code, pull requests, secrets, and workflows so it can scan and open fix PRs. Click **Install**.

![Install the App on your organization](images/github_install_app.png)

## Connect GitLab

Sensei also supports **GitLab**, both **gitlab.com** and **self-managed** instances. Instead of a GitHub App, GitLab connects with a **project or group access token** plus a webhook; Sensei uses that token to scan, open merge requests, and apply fixes.

From the Sensei hub, choose **Add Repositories** (or **Connect** on the Connections page) to open **Set Up Sensei**, then select **GitLab** as the source-control provider.

### Step 1: Create an access token

In GitLab, open the project (or group) you want to scan and go to **Settings → Access tokens → Add new token**:

- **Role:** **Developer**, enough to push fix branches and open merge requests. Choose **Maintainer** if the project's push rules require it.
- **Scopes:** **`api`** and **`write_repository`**.

Create the token and copy the generated `glpat-…` value (GitLab shows it only once).

> **🔑 Tip:** A **group** access token onboards any project in that group; a **project** access token is scoped to the single project.

### Step 2: Connect

Back in **Set Up Sensei** with **GitLab** selected, fill in:

- **GitLab Base URL:** `https://gitlab.com`, or your self-managed instance URL (for example `https://gitlab.example.com`).
- **Access Token:** the `glpat-…` token from Step 1.
- **Webhook Secret:** leave blank to auto-generate (recommended). You'll add this secret to the webhook in the next step.

Click **Connect GitLab**. DefectDojo validates the token, stores it encrypted, and can then list projects, open merge requests, and run scans.

### Step 3: Add the webhook

So DefectDojo receives push, merge-request, and comment events, add a webhook to **each** GitLab project you plan to onboard (**Settings → Webhooks → Add new webhook**):

- **URL:** the webhook URL shown on the Set Up Sensei page (`https://<your-defectdojo-host>/sensei/gitlab/webhooks`).
- **Secret token:** the webhook secret from Step 2.
- **Trigger events:** enable **Push events**, **Merge request events**, and **Comments**.

Leave SSL verification enabled, click **Add webhook**, then use **Test → Push events** to confirm DefectDojo responds with **HTTP 200**.

After connecting, click **Choose projects** and continue with [Select repositories](#select-repositories); onboarding, configuration, and scanning work the same as GitHub.

> **GitLab equivalents:** where this guide says *pull request*, GitLab uses a **merge request**; the pull-request **status check** is posted as a GitLab **commit status** on the merge request's head commit.

## Select repositories

After the App is installed, DefectDojo shows the repositories it can access. Only repositories Sensei has **push access** to are listed; remediation works by pushing a branch and opening a pull request, so repositories without push access are hidden. A pull request is opened against each repository's **default branch**.

![Select repositories to onboard](images/setup_repo_picker.png)

Use **Add** to select one or more repositories, then click **Configure N repo(s)**.

## Configure a repository

The **Configure Repository** form controls how Sensei scans and reports on the repository.

![Configure a repository](images/repo_config.png)

- **Scanning Mode (DefectDojo-hosted):** scans run in DefectDojo. Nothing is added to your repository; trigger scans on demand or automatically via the GitHub App.
- **PR Reporting:** choose what Sensei posts back on pull requests:
  - Post a status check on the pull request.
  - Fail the check when net-new findings are introduced.
  - Post a results summary comment on each commit.
  - Auto-create the base-branch baseline on the first PR.
- **Automated Fixes:** enable *Stage matching findings for one-click auto-fix after each scan* to have Sensei stage candidates automatically (see below).

### Automated fix criteria

When automated fixes are enabled, findings that meet your criteria are staged as **candidates** on the Sensei page after each scan. Nothing runs (and no LLM cost is incurred) until you approve, unless you enable automatic remediation.

![Automated fix criteria and advanced options](images/repo_config_advanced.png)

- **Severity threshold:** findings at or above this severity qualify (choose *Any* to gate on risk only).
- **Risk threshold:** findings at or above this risk level also qualify (combined with severity using OR).
- **Open fix PRs against branch:** the branch auto-fix pull requests target; overridable per fix when you approve individually.
- **Exclude findings tagged:** skip findings carrying the tags you list (e.g. `no-fix`).
- **Automatically remediate candidates:** when enabled, a background check (about every 5 minutes) opens fix pull requests for this repo's staged candidates without waiting for approval, until your fix quota is reached. Leave off to review and approve each candidate yourself.

Under **Advanced options** you can link the repository to an existing product/asset or create a new one, set the organization, and set a minimum severity below which findings are neither reported nor used in the merge gate.

## Onboard

Click **Onboard for hosted scanning**. The repository appears on the Sensei hub with a status of **Active**, ready to scan. From here, continue to [Fixing findings with Sensei](/sensei/fixing_findings/).
