---
title: "The Markdown Editor"
description: "Format text, and paste or drag images directly into any DefectDojo Pro description, note, or other markdown field"
weight: 11
audience: pro
---

Most long-form text in the DefectDojo Pro UI is written in the same markdown editor. It appears on Findings, Notes, Engagements, Tests, Assets, Groups, Finding Templates, Mitigation Policies, the Markdown dashboard widget, and the Rules Engine "add note" action, so the formatting and image behavior described here is the same everywhere you meet it.

## Formatting

The toolbar above the editor covers the common cases: headings, **bold**, *italic*, underline, block quotes, bullet and numbered lists, links, and fenced code blocks. Markdown you type is recognized as you go, and tables are supported.

To read a value exactly as it was typed rather than as formatted text, use the toggle in the top right of the displayed text.

## Adding images

You can put a screenshot straight into any markdown field without uploading it somewhere else first. There are three ways:

* **Paste** an image from your clipboard into the editor.
* **Drag and drop** an image file onto the editor.
* Use the **Insert image** button in the editor toolbar to pick a file.

DefectDojo stores the image and inserts it into the text as a markdown image, so it appears wherever that text is shown: the object's page, the notes feed, and generated reports (PDF and HTML alike).

A few details worth knowing:

* PNG, JPEG, GIF and WebP images are accepted, up to 10 MB each.
* Images are only shown to users who are signed in. The link in the text is unguessable, so an image is visible to whoever can read the text that contains it.
* Only images stored by DefectDojo are rendered. A markdown image pointing at an outside website is not displayed, which keeps imported scan text from loading remote content.
* An image that is uploaded but never saved, or that is later removed from every field that used it, is cleaned up automatically after two days.

### Images in tickets pushed to another tool

When a description is pushed to an issue tracker (Jira, ServiceNow, GitHub, GitLab, Linear, or Azure DevOps), the image itself is not copied into the ticket. The ticket instead carries a line naming the screenshot and linking back to it in DefectDojo, and opening that link requires signing in. This keeps a stored image from being exposed to everyone who can read the ticket, and avoids a broken image in trackers that cannot reach your DefectDojo instance.

Images placed inside the text are separate from file attachments. Attachments live in their own tab and are listed and downloaded separately; see [Attaching Files](/triage_findings/findings_workflows/pro__add_files/).
