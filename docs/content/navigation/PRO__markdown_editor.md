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

Images placed inside the text are separate from file attachments. Attachments live in their own tab and are listed and downloaded separately; see [Attaching Files](/triage_findings/findings_workflows/pro__add_files/). An attached image can also be shown inside the text, as described below.

## Adding images through the API

Scripts and integrations can put images into markdown fields too, using a normal API token (`Authorization: Token <your API key>`). There are two ways, and both end with a markdown image in the text.

### Reference an image attached to a Finding, Test or Engagement

If your automation already attaches screenshots to an object's Files, reference that attachment from the object's text and DefectDojo displays it there.

1. Attach the image: `POST /api/v2/findings/{id}/files/` as `multipart/form-data`, with a `title` and the `file`. Tests and Engagements have the same endpoint.
2. Read the attachment's link: `GET /api/v2/findings/{id}/files/` lists each attachment with its `file` link.
3. Write the text: include `![Image](<the file link>)` in the description (or another markdown field) with a `PATCH` to `/api/v2/findings/{id}/`.

```bash
curl -s -H "Authorization: Token $DD_API_KEY" \
     -F "title=login-page.png" -F "file=@login-page.png" \
     https://defectdojo.example.com/api/v2/findings/123/files/

curl -s -H "Authorization: Token $DD_API_KEY" \
     https://defectdojo.example.com/api/v2/findings/123/files/
```

The link returned when a file is uploaded, and the attachment's download link (`/api/v2/findings/{id}/files/download/{file_id}/`), work too. The link must point at your own DefectDojo, either as returned or as a path starting with `/`; an image on another site is not displayed.

An attached image is shown only to users who may view that object's files, and it disappears from the text if the attachment is deleted.

### Upload an image for any markdown field

Objects without a Files tab (Assets, Groups, Finding Templates, Mitigation Policies, Notes and others) take an uploaded image instead, the same kind the editor stores when you paste one.

1. Upload the image: `POST /api/v2/inline_images/` as `multipart/form-data`, with the file in the `image` field. PNG, JPEG, GIF and WebP images up to 10 MB are accepted.
2. Write the text: the response includes a ready-made `markdown` value. Put it into any markdown field through that object's normal endpoint.

```python
import requests

BASE = "https://defectdojo.example.com"
HEADERS = {"Authorization": "Token <your API key>"}

with open("login-page.png", "rb") as handle:
    image = requests.post(f"{BASE}/api/v2/inline_images/", headers=HEADERS, files={"image": handle}).json()

requests.patch(
    f"{BASE}/api/v2/findings/123/",
    headers=HEADERS,
    json={"description": f"Login bypass, see below.\n\n{image['markdown']}"},
)
```

A few details worth knowing:

* Use the `markdown` (or `url`) value exactly as returned. Adding your server's address in front of it stops the image from displaying.
* Embed the image within two days of uploading it. An upload that no field uses by then is cleaned up automatically, as it is for images pasted into the editor.
* `GET /api/v2/inline_images/{id}/` returns an image's details, and `GET /api/v2/inline_images/{id}/download/` returns the image itself.
* The full request and response formats are in the API documentation under `/api/v2/oa3/swagger-ui/`.
