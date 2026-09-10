---
title: "Support"
description: "Filing a support request from DefectDojo Pro, the documentation search above the form, the community board, and the settings that cover self-hosted and airgapped instances"
weight: 11
audience: pro
---

DefectDojo Pro carries two support pages. **Support** is where you file a request and follow it. **Community requests** is the board of topics DefectDojo has published for customers to vote on.

> The Support pages are a DefectDojo Pro feature. The instance calls DefectDojo from its own server, never from your browser.

## Support requests

**Support** (`/cloud/support`) holds one form and one list.

The form takes four kinds of request:

| Kind | Use it for |
| --- | --- |
| **Feature request** | Something DefectDojo does not do yet. |
| **Connector or parser request** | A tool you want DefectDojo to read from. |
| **Bug report** | Something that does not work as documented. |
| **General feedback** | Anything that is not one of the three above. |

Under the form, **My requests** lists everything your account has filed, with the status DefectDojo staff last set on it. If the instance cannot reach DefectDojo, the list falls back to the copy the instance stores locally and the page says the status updates are paused.

## Community requests

**Community requests** (`/cloud/support/community`) lists the topics DefectDojo has published. Each row carries a title, a status and a vote button. Vote once per topic to say it matters to you. The count rises and the button locks.

A request you file does not reach the board on its own. DefectDojo staff decide what to publish there.

## The documentation search

A search box sits above the request form. Type a question into it and it lists the documentation pages that match, so you can answer the question before you file anything. Select a page to open it in a new tab.

The instance's own server reads the published documentation index (see `DOCS_SEARCH_URL` below) and keeps it for an hour. Your browser never calls the documentation site.

A lookup that fails leaves the form usable. The box shows no matches and you file the request as normal. A failed lookup is remembered for a minute, so an outage at the documentation site does not slow down every keystroke.

## Self-hosted instances

A self-hosted instance enrols with DefectDojo using its own signed license rather than a portal secret. Enrolment happens on the first support call and needs no extra configuration.

**One instance per license holds the enrolment at a time.** If a second instance running the same license enrols, it takes the enrolment over and the first instance can no longer reach DefectDojo. The instance that lost it writes an error to its log naming its own key, and it does not re-enrol on its own. Run one enrolled instance per license, and decide which one that is.

An enrolment key that DefectDojo staff have revoked cannot be replaced by the instance. The instance logs the refusal and the support pages stay unavailable until staff clear the key.

If enrolment is refused for any other reason, the log line names the credential the instance presented, so you know whether to check the license or the portal secret.

## Airgapped instances

An instance with no route off its network cannot use the support pages at all. Set `DD_AIRGAPPED` and both pages open a dialog that says support tracking is not supported for airgapped instances, with an address to write to instead.

With the setting on, the instance makes no outbound support call and no documentation call. The dialog opens as soon as the page loads. It does not wait for a call to time out first.

## Settings

| Setting | Type | Default | What it does |
| --- | --- | --- | --- |
| `DD_AIRGAPPED` | boolean | `False` | Blocks both support pages and shows the airgapped dialog. |
| `SUPPORT_EMAIL` | string | `support@defectdojo.com` | The address the airgapped dialog tells people to write to. |
| `DOCS_SEARCH_URL` | string | `https://docs.defectdojo.com/search-index.json` | The documentation index the search box reads. |
