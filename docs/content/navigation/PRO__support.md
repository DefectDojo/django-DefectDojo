---
title: "Support"
description: "Filing a support request from DefectDojo Pro, the documentation and community search above the form, the community board, and the settings that cover self-hosted and airgapped instances"
weight: 11
audience: pro
---

DefectDojo Pro carries two support pages. **Support** is where you file a request and follow it. **Community requests** is the board of topics DefectDojo has published for customers to vote on.

> The Support pages are a DefectDojo Pro feature. The instance calls DefectDojo from its own server, never from your browser.

## Support requests

Open **Support** from **Settings → Support**, or from **Settings → License & Support → Support** in the reorganized settings menu. It shows on cloud, self-hosted and airgapped instances. The page (`/ui/cloud/support`) holds a search box, a request form behind a link, and a list.

The form takes four kinds of request:

| Kind | Use it for |
| --- | --- |
| **Feature request** | Something DefectDojo does not do yet. |
| **Connector or parser request** | A tool you want DefectDojo to read from. |
| **Bug report** | Something that does not work as documented. |
| **General feedback** | Anything that is not one of the three above. |

Under the form, **My requests** lists everything your account has filed, with the status DefectDojo staff last set on it. If the instance cannot reach DefectDojo, the list falls back to the copy the instance stores locally and the page says the status updates are paused.

## Community requests

**Community requests** (`/ui/cloud/support/community`) lists the topics DefectDojo has published. Each row carries a title, a status and a vote button. Vote once per topic to say it matters to you. The count rises and the button locks. Completed topics (Shipped, Merged, Aged out) sit greyed out at the bottom of the board and no longer take votes. If DefectDojo decides not to pursue a topic, it leaves the board; a request you linked to it stays in **My requests**. When a topic you voted on changes status, DefectDojo e-mails the address on your DefectDojo user, provided it is at your organization's e-mail domain (the domain of your Cloud Portal account).

A request you file does not reach the board on its own. DefectDojo staff decide what to publish there.

## The documentation and community search

A search box sits at the top of the page. Type a question into it and it lists the open community requests that match, up to three, then the documentation pages that match, so you can find an answer or an existing request before you file anything. Select a community request to open the community board with that request outlined and scrolled into view. Select a documentation page to open it in a new tab.

The request form stays hidden until you select **Can't find what you're looking for?** under the box.

The instance's own server reads the published documentation index at `docs.defectdojo.com` and keeps it for an hour. Your browser never calls the documentation site.

A lookup that fails leaves the form reachable. The box shows no matches and you file the request as normal. A failed lookup is remembered for a minute, so an outage at the documentation site does not slow down every keystroke.

## Self-hosted instances

Support works the same way on a self-hosted instance. The instance enrols with DefectDojo using its own signed license rather than a portal secret. Enrolment happens on the first support call and needs no extra configuration.

The instance calls `cloud.defectdojo.com` for support requests and the community board, and `docs.defectdojo.com` for the documentation search. Allow outbound HTTPS to both. If the instance has no route off its network, turn on **Airgapped instance** instead (see below).

**One instance per license holds the enrolment.** The first instance to enrol keeps it. A second instance running the same license is refused: it writes an error to its log naming its own key, and its support pages stay unavailable. To move the enrolment, ask DefectDojo support to reset it, then open the support pages on the instance that must keep it. The next instance to make a support call enrols.

A key that DefectDojo staff revoke stops working at once. The instance cannot replace it on its own, and its support pages stay unavailable until staff reset the enrolment.

A connector request from a self-hosted instance cannot carry tool details or credentials, because DefectDojo accepts those only from a cloud instance. The form says so. Send the request, then e-mail the details to `support@defectdojo.com`.

If enrolment is refused for any other reason, the log line names the credential the instance presented, so you know whether to check the license or the portal secret.

## Airgapped instances

An instance with no route off its network cannot use the support pages at all. Turn on the **Airgapped instance** feature flag under **Settings → Feature Flags**. Both pages then open a dialog that says support tracking is not supported for airgapped instances, with the DefectDojo support address to write to instead. Its **Go back** button returns you to the page you came from. The flag takes effect on the next page load; no restart is needed.

With the setting on, the instance makes no outbound support call and no documentation call. The dialog opens as soon as the page loads. It does not wait for a call to time out first.

## Settings

The support pages need no environment variables. The one switch, **Airgapped instance**, is a feature flag under **Settings → Feature Flags** (off by default). The dialog address is `support@defectdojo.com`.
