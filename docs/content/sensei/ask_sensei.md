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

Ask Sensei is in beta and is switched on per instance. It requires the Sensei license and the
global **Maintainer** or **Owner** role.

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
only the person who asked can open them, whatever the other person's role. Delete a conversation from the same list.

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

An answer can offer to mark findings as **verified**, **false positive**, **out of scope** or
**mitigated**, but only findings that its own queries returned. Clicking the button shows how
many findings the change covers and asks you to confirm. The change runs with your
permissions, exactly like the same change made from the findings bulk-edit panel: findings you
cannot edit are skipped.

Each change is recorded in the audit log like any other, with a marker linking it to the
question that proposed it, and the answer shows that it was applied.

## What is sent to the AI model

To answer, the model is sent your question, the name of the page you asked from and the record
ids on it, a short summary of the earlier questions in the conversation, and the results of the
queries it runs. Those results include finding titles, severities, Asset names and, when it
looks up one finding, that finding's description and mitigation text, truncated.

Text that came from scanners and imports is treated as data, never as instructions. The views
an answer can use are a fixed set built into DefectDojo; the model cannot add new ones, run
code in your browser, load images, or link outside DefectDojo. External links in an answer are
shown as plain text.

## Limits and cost

Each instance has an allowance of answers in its license, and each person can ask a limited
number of questions per hour. One question per person is answered at a time; **Stop** cancels
one in progress. Questions that fail do not count against the allowance.

On self-hosted installations Ask Sensei uses the AI provider configured under
[AI Model Settings](../ai_model_settings).
