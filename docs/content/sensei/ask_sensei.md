---
title: "Ask Sensei"
description: "Ask a question from any page and get an answer built from live, interactive views of your own data."
draft: false
audience: pro
weight: 6
---

**Ask Sensei** answers questions about your findings, Assets and trends from anywhere in the
DefectDojo Pro UI. Instead of a block of text, an answer is composed from the same kinds of views
the rest of the product uses: headline numbers, charts, tables, lists of findings that link to
each finding, a small what-if calculator, and follow-up questions you can pick with one click.
When an answer suggests a change, such as marking findings as verified, it offers a button, and
nothing changes until you confirm.

Ask Sensei is in beta and is switched on per instance. It requires the Sensei license. Any
signed-in user can ask: answers draw only on data that user can see, and an answer offers a
change only on findings that user can edit.

## Asking a question

Open the assistant in any of three ways:

- the **Ask Sensei** button in the sidebar footer;
- the command palette (**Cmd+K** or **Ctrl+K**): type a question and pick **Ask Sensei**, the
  first result;
- from a record: **Explain With Sensei** on a finding's menu, or **Summarize With Sensei** on an
  Asset's menu.

The assistant opens in a panel on the right and stays open as you move between pages, so you
can follow a link in an answer and keep the conversation in view. The page you ask from is part
of the question: asked from a finding, "how risky is this?" is about that finding.

Your conversations are listed under the history button in the panel. They are private: in the app,
only the person who asked can open them, whatever the other person's role. Deleting a conversation removes it from your list. DefectDojo keeps it, so a change made from one of its answers stays traceable in the audit log.

**Simple Answers**, at the top of the panel, asks for short, text-first answers with fewer
charts.

## Where the numbers come from

Every number in an answer comes from your data, read with **your** permissions, at the moment
you asked. Sensei looks the data up with the same queries the findings list and the dashboard
widgets use, so an answer shows nothing you could not see yourself and agrees with your
dashboards.

Sensei never types a number into a chart or a headline tile. It chooses which query to run and
which view to show; DefectDojo fills the view in from the query's result. Open **How Sensei
Answered** under an answer to see every query it ran.

An answer is kept as it was shown. Reopening a conversation next month shows what you saw then,
not what the data says now. Ask again for current numbers.

## Changing findings from an answer

An answer can offer to change findings: mark them **verified**, **false positive**, **out of
scope** or **mitigated**, set their severity, add a note, add tags, or push them to Jira. It
offers a change only on findings its own queries returned and that you can edit. A status change
is offered only on findings shown as open (and, for **verified**, not yet verified), so an
answer never offers to reopen a closed finding. Clicking the button shows what will change and
lists the findings by title, and nothing changes until you confirm. The change runs with your
permissions, exactly like the same change made from the findings bulk-edit panel.

Each change is recorded in the audit log like any other, with a marker linking it to the
question that proposed it and whether that question was typed or spoken, and the answer shows
that it was applied.

An answer can also offer to open a page: a list such as findings, Assets or risk acceptances,
the dashboard, or a record its queries returned. Ask Sensei cannot delete anything or change
users, groups, roles, settings, credentials or the license. Asked to, it says so and offers to
open the closest page instead.

## Voice

Where voice is switched on for the instance, the panel shows a microphone next to **Ask**.
Press it, or **Ctrl+Shift+Space** while the panel is open, and speak a question. The words
appear in the question box for you to check and edit before you press **Ask**. Turn on **Send
When Recognized** to send a spoken question as soon as it is recognized.

By default speech is recognized on your own computer: the audio never leaves it, and only the
text of the question reaches DefectDojo. This works in Chrome and Edge on the desktop, which
download a speech model for your language the first time. Other browsers show the microphone
with a note that they cannot recognize speech on the device. An administrator can instead have
short recordings transcribed by the instance's AI provider (Gemini on Vertex, or an
OpenAI-compatible provider); the recording is sent once to that provider and is not stored. On
self-hosted installations this is the `DD_ASSISTANT_VOICE_ENGINE` setting: `on_device` (the
default), `provider`, or `off` to remove the microphone.

The microphone listens only after you press it, for one sentence, and never while Sensei is
speaking. You can also say the label of a button in the latest answer, such as "Open Top
Finding", to press it:

- A button that only opens a page opens it.
- A change to one finding that stays in DefectDojo and is easy to undo (verifying it, setting
  its severity, adding a note or tags) asks you to say **confirm** or **cancel**, after reading
  back the change and the finding's title. Sensei listens once for the answer.
- Anything else opens the confirmation dialog and waits for a click: a change to several
  findings, a false positive (which can spread through false-positive history), marking a finding
  mitigated or out of scope (which closes it, and can close its Jira issue), or a push to Jira.
  Voice cannot confirm these.

When a spoken question's answer only takes you somewhere ("open the dashboard"), the panel
goes there without a click.

**Read Answers Aloud**, off by default, reads a one- or two-sentence summary of each answer with
a voice installed on your computer. Every number in that summary is filled in by DefectDojo from
the same queries the answer shows. Languages with no voice installed on the computer are not
read aloud.

## What is sent to the AI model

To answer, the model is sent your question, the name of the page you asked from and the record
ids on it, a short summary of the earlier questions in the conversation, and the results of the
queries it runs. Those results include finding titles, severities, Asset names and, when it
looks up one finding, that finding's description and mitigation text, truncated.

Text that came from scanners and imports is treated as data, never as instructions. The views
an answer can use are a fixed set built into DefectDojo; the model cannot add new ones, run
code in your browser, load images, or add links: link syntax in an answer's text is shown as
plain text, and web addresses are shown as code you can copy. To take you somewhere, an answer
offers a button, and buttons only lead to pages inside DefectDojo.

## Limits and cost

Each instance has an allowance of answers in its license, and each person can ask a limited
number of questions per hour (40 by default). One question per person is answered at a time; **Stop** cancels
one in progress. Questions that fail do not count against the allowance.

On self-hosted installations Ask Sensei uses the AI provider configured under
[AI Model Settings](../ai_model_settings).
