---
title: "Language and Localization"
description: "Choose the language DefectDojo's interface is shown in, and understand which languages are offered and what stays in English"
weight: 12
---

DefectDojo can show its interface in a language other than English. The choice belongs to each
user, not to the instance: two people signed in to the same DefectDojo can read it in two
different languages, and neither setting affects the other.

## Choosing a language

Open the **language** button and pick from the list. Where that button is depends on which
interface you are in:

- **DefectDojo Pro**: the globe icon in the sidebar, between your account button and the alerts
  bell. The interface switches as soon as you choose, with no reload.
- **DefectDojo (open source)**: the **Language** field on your profile page, saved with the rest
  of the form.

Both write the same setting, so choosing a language in one interface changes it in the other.
The choice follows your account rather than the browser: sign in from a different computer and
the interface is already in the language you picked.

## Which languages are offered

The menu lists only languages whose translations are complete. A language is added to the list
when every message in the interface has been translated and checked, so you should never see a
page that is half translated. Languages still being worked on are not offered at all.

English is always available and is the language a new account starts in, unless an administrator
has set a different default for the instance.

Right-to-left languages (Arabic, Hebrew, Persian, Urdu) are held back until the mirrored layout
has been verified, so they do not appear in the menu yet even where their translations exist.

## What is translated, and what is not

**Translated**: menus, buttons, headings, form labels, help text, confirmation dialogs, table
column headers and the messages DefectDojo shows you.

Notifications are translated too, and in **your** language rather than the language of whoever
caused them. If a colleague reading DefectDojo in German does something that notifies you, the
email you receive is in the language you chose.

**Not translated**, deliberately:

- **Your data.** Finding titles, asset and organization names, descriptions, tags, notes and
  anything else you or your tools entered stays exactly as written. A finding imported from a
  scanner reads the same in every language.
- **Values the API uses.** A finding's severity is `Critical` in every language: what changes is
  the label on screen, not the value stored, exported or sent to an integration. Automation
  written against the API keeps working, and a report exported in one language carries the same
  values as the same report exported in another.
- **Commands, settings names and identifiers.** A management command, an environment variable
  and a CVE identifier are the same everywhere.
- **Content from connected tools.** Text that Jira, a scanner or another integration supplies is
  passed through as it arrives.

## Machine translation

Translations other than English are machine generated and reviewed for completeness rather than
for style. They are accurate enough to work in, and they are corrected over time. If a phrase
reads badly in your language, tell your DefectDojo contact: the fix is applied to the whole
interface rather than to that one screen.

## For administrators

The instance's default language is `DD_LANGUAGE_CODE` (default `en-us`). It applies to anyone who
has not chosen a language and to places that run without a signed-in user, such as a scheduled
notification.

A user's language is stored on their profile, so you can set it for them from the user
administration page in the same place you set their other contact details.

A notification addressed to a person is written in that person's language, whichever language the
event was triggered from. Destinations that are not a person use the instance default instead: a
Slack or Microsoft Teams channel, a webhook, and the instance-wide notification email address are
read by many people with different preferences, so one language has to be chosen for them.
