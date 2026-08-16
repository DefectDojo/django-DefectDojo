---
title: "Claude Code Plugin"
description: "Query, triage, import and report on DefectDojo Pro data from Claude Code"
draft: false
audience: pro
weight: 24
---

<span style="background-color:rgba(242, 86, 29, 0.3)">Note: AI features are a DefectDojo Pro-only feature.</span>

The DefectDojo plugin for Claude Code brings your vulnerability data into the
terminal where your team already works. Your Pro instance already speaks MCP;
the plugin teaches a coding agent what to do with it, and adds the operations
the read-only [MCP Server](../mcp_server_pro/) does not cover, such as changing
finding status and importing scans.

If you want to connect a chat assistant such as Claude Desktop or claude.ai to
DefectDojo, use the [MCP Server](../mcp_server_pro/) page instead. This page is
specifically for Claude Code, the command-line coding agent.

## Install

```
/plugin marketplace add DefectDojo/agent-skills
/plugin install defectdojo@defectdojo
```

When you enable the plugin it asks for two things:

- **Instance URL**, for example `https://yourcompany.cloud.defectdojo.com`, with
  no trailing slash and no path.
- **API v2 key**, which you create from your user profile in DefectDojo.

The key is stored in your operating system keychain. Start a new session
afterwards so the MCP server connects.

Then ask for something:

> What are the top 10 findings we should fix first?

## Prerequisites

- DefectDojo Pro v2.51.2 or later, with the MCP server enabled. See
  [MCP Server](../mcp_server_pro/) for how an administrator turns it on.
- Claude Code 2.1.143 or later, so that installing the umbrella plugin enables
  its components automatically.
- macOS or Linux, including WSL. Native Windows is not supported yet.

The plugin requires DefectDojo Pro and refuses to run against DefectDojo open
source. It verifies the edition on first contact and stops with an explanatory
message rather than partially working.

## What you can ask for

Installing `defectdojo` installs the full set. You can also install any single
plugin; each one pulls in the connection plugin automatically.

| Plugin | Skills | Ask it for |
| --- | --- | --- |
| `defectdojo-connect` | `connection-doctor` | "Is DefectDojo connected?", or any 401, 403 or missing-tool problem |
| `defectdojo-triage` | `findings-query`, `triage-findings` | "How many criticals are open?", "Mark these false positive", "Give me a brief" |
| `defectdojo-import` | `import-scans`, `wire-ci-import` | "Get this Semgrep output into Dojo", "Push our scans from CI" |
| `defectdojo-report` | `security-report` | "Build the quarterly report for the board" |

### Asking questions

Questions are answered from your live data, and counts always state what they
counted:

> How many critical findings are open in the payments app?
>
> What changed this week?
>
> Which products have the worst backlog?

For anything phrased as "top", "worst" or "what should we fix first", the plugin
ranks by DefectDojo's own priority, which weighs exploitability, threat
intelligence, reachability, business context and many more signals, rather than
by severity alone.

### Triaging findings

The triage skill changes finding state: close, verify, mark false positive, mark
out of scope, risk accept, add notes and tags, and merge duplicates.

It always shows you a table of proposed changes and waits for you to confirm
before writing anything, and it records a note on every change so the reason
survives for the next person who looks.

### Importing scans

> Get this semgrep.json into Dojo under the payments product.

The import skill identifies the scan type, chooses import or reimport correctly,
creates the product and engagement if you ask it to, and waits for background
processing to finish before reporting results. It can also add scan upload to
your CI pipeline, using a service account rather than a personal token.

## How it connects

You enter credentials once, and two channels derive from that single entry.

**MCP** connects Claude Code to the MCP server built into your instance at
`https://your-instance/mcp`. That provides the read tools, which appear as
`mcp__defectdojo__*`.

**REST** covers everything the read tools do not: status changes, notes, imports
and reporting. The plugin bundles a single command that handles the auth header,
error translation and background-import polling.

Your token is never shown to the model, and never appears on a command line.
Every action runs as you, under your existing DefectDojo permissions: the plugin
cannot do anything in DefectDojo that you cannot do yourself.

### Using it in CI

Rather than configuring the plugin, set two environment variables:

```
DD_BASE_URL=https://your-instance.example.com
DD_API_TOKEN=<a service account API key>
```

Use a dedicated service account rather than a personal token. Personal tokens
expire and carry one person's permissions, which is the usual reason a pipeline
that worked for months suddenly stops.

## Troubleshooting

Ask the plugin first:

> Is my DefectDojo connection working?

The connection doctor probes each layer in order and tells you which one failed
and what to do about it. The most common causes:

| Symptom | Cause |
| --- | --- |
| Tools missing, but other calls work | The MCP server is disabled on the instance, or the session started before you configured the plugin. Start a new session. |
| Everything returns 401 | The API token expired. DefectDojo tokens can expire. Create a new one, update it through `/plugin`, and start a new session. |
| One operation returns 403 | Your DefectDojo role does not permit that action on that object. |
| The plugin says the instance is not Pro | The URL includes a path, a proxy is returning its own 404, or the instance is DefectDojo open source, which is not supported. |

## Source and support

The plugin is open source at
[github.com/DefectDojo/agent-skills](https://github.com/DefectDojo/agent-skills).
Report problems as issues there.
