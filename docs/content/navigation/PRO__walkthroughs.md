---
title: "In-App Walkthroughs"
description: "Guided, step-by-step tours of the DefectDojo Pro UI: the App Tour, the tours for each area, the first-visit offer, and turning the offer off per user"
weight: 9
audience: pro
---

A walkthrough guides you through the Pro UI one area at a time. Each step outlines part of the page and dims everything else, and a small card beside the outline says what the area is for. Only the outlined area and the card respond to clicks while a step is showing, so nothing else on the page can be changed by accident.

Where there is more to read, the card has a **Learn more** link to the matching part of this documentation. It opens in a new tab, so the walkthrough stays where it is.

Some steps move on when you select **Next**. Others move on when you do the real thing, such as opening a menu or a record, and the card says which. The walkthrough never clicks anything for you.

## The lightbulb

A yellow lightbulb in the lower right corner of every page opens the list of walkthroughs. Walkthroughs made for the page you are on come first, under **This Page**, followed by the ones you can take from anywhere, under **General**. Each entry reads **Take the Tour**, **Resume Tour** or **Retake the Tour**, depending on how far you got last time.

The list only ever holds walkthroughs for features you can use. A walkthrough for a feature that is turned off on your instance, or that your role does not give you access to, does not appear in the lightbulb at all, and it is never offered to you.

**All Walkthroughs**, at the top of the list, opens every walkthrough you can take in one table, not just the ones for this page. Each row shows whether you have not started it, are part-way through, or have completed it, and its menu takes, resumes, retakes or restarts it.

A small dot on the lightbulb means a walkthrough in the list is one you have not seen yet. The lightbulb steps aside while a walkthrough is running, and it is not shown on phone-sized screens.

To hide the lightbulb, open your **User Profile**, clear **Show the Walkthrough Lightbulb** under **Walkthroughs**, and save. Check it again to bring it back.

## Turning walkthroughs on

Walkthroughs are a **beta** feature and are **on by default**. A superuser can turn them off for the whole instance under **Settings > Feature Flags** (**In-App Walkthroughs**). While the flag is off, no walkthrough is offered, the lightbulb is hidden, and no progress is recorded.

## The App Tour

The App Tour follows the loop DefectDojo is built around, from **Home** to a single finding:

1. **Home** and the Command Center.
2. The Assets (or Products) entry in the sidebar, which you open to reach the full list.
3. The asset list, then one asset you open from it.
4. That asset's findings, then one finding you open from them.
5. The finding's page and its gear menu, where most actions on a finding live.

The App Tour is listed under **This Page** on Home and under **General** everywhere else. Wherever you start it, it begins on Home.

The tour works with whatever you can see. With no finding to open, it skips the steps that open one; with no asset either, it skips those too. Its last step then says that the rest of the tour is there to take once there are findings to open. This covers a new, empty instance and a user who has not been given access to anything yet.

When the [sandbox](/admin/sandbox/pro__sandbox/) is turned on, a tour that has nothing to open also says so on its first and last steps, with an **Open the Sandbox** button. The sandbox usually holds sample data, and the button starts the App Tour again there, with every step. The tour you were taking ends when you leave for the sandbox, and the note does not appear inside the sandbox itself.

The tour starts with whichever asset and finding it finds first, but you can open any other row in the list instead. The rest of the tour follows the record you opened.

If the sidebar is collapsed to its icon rail, the tour expands it for the sidebar step and collapses it again when the tour ends.

### Starting, stopping and retaking the tour

* Start it from the lightbulb.
* Stop at any time with the **X** on the card or the **Escape** key. The step you reached is remembered, and the lightbulb then offers **Resume Tour**.
* If you navigate somewhere the tour did not expect, including with the browser's Back button while a step is still loading, it pauses and a banner offers **Resume** or **Stop**. Reloading the page during a tour shows the same banner.
* If a step's part of the page does not appear (a slow page, or a record that is not there), the card says so and offers **Try Again**, **Skip** and **Stop**. The tour never moves on by itself.
* If you open something from the page during a step, such as an action from a gear menu that opens a dialog, the tour steps out of the way while the dialog is open, and comes back when it closes.
* Once you finish, the lightbulb offers **Retake the Tour**, and you can take it as often as you like.

On a phone-sized screen the card becomes a sheet along the bottom of the screen, or along the top when the outlined area is in the lower half, so it never covers what it points at.

## Tours by area

Beyond the App Tour, each area that people ask about most has its own tour. A tour is listed in the lightbulb under **This Page** on the pages it covers, and the ones marked *General* are also listed everywhere else. Like the App Tour, each one works with whatever you can see: it picks a real record to walk through, and skips the steps that need one when there is none. A step that needs a permission you do not have is skipped too.

| Tour | Listed on | What it covers | Who sees it |
|---|---|---|---|
| **Why Findings Close and Reopen** | A Test and a Finding | The Import History counts, the notes a Reimport writes, the three causes behind most reopened Findings, the statuses a Reimport never reopens, and how Reimport matching works | Anyone who can view the Test. The last step, Matching Configuration, needs permission to view Dedupe Pools |
| **Organizations, Assets, Engagements and Tests** (or Product Types, Products, Engagements and Tests) | Organization, Asset, Engagement and Test pages; *General* | How the four levels fit together, from the Organization list down to a Test's Import History, and where an import puts its Test | Anyone. The import step needs permission to import scan results |
| **Finding Statuses, SLAs and Risk Acceptance** | The Findings lists, Risk Accepted Findings, Risk Acceptances and a Finding | What each status means, where an SLA deadline comes from, closing without a fix, and the two lists that show accepted risk | Anyone. The Risk Acceptances steps need permission to view risk acceptances |
| **The Findings List** | Every Findings status list | Filters and sort, Keyword Search, saved Views, Columns, and selecting Findings for bulk actions | Anyone. Views and Columns are skipped when page layouts are locked |
| **Exporting Findings** | Every Findings list | That an export follows the list's filters, the Export menu and its formats, and choosing the fields | Anyone who can view Findings |
| **API Access** | The API token page; *General* | Where the API key is, the header it goes in, regenerating it, getting it from a script, the API docs, and automating against `/api/v2/` | Anyone |
| **Reports** | The Reporting pages | Templates, blocks and themes, generating a report, output formats, and finding the file under Generated Reports | Users who can view generated reports, when Reporting is turned on |
| **SSO and Login** | Authorization and the login and provider settings pages | Configured versus enabled providers, the password and auto-redirect switches, creating users on first login, keeping a way back in, and why a new SSO user sees nothing yet | Users who can view identity providers. The login switches need permission to change them |
| **Classic Jira or the Jira Connector** | The Downstream connector and Jira pages | Which Jira integration is which, whether to move to the connector, and which push to use on a Finding | Users who can view integrations, when Downstream connectors are turned on |
| **Locations** | The Locations pages | What replaced Endpoints, where the Locations lists are, and a Location's status, the Assets that reference it and its open Findings | Users who can view Locations, when Locations are turned on |
| **Upstream Connectors** | The Upstream connector and records pages | Configured and available connectors, a connector's unmapped and mapped records, and its Operations history | Users who can view connectors |

## The first-visit offer

The first time a user opens **Home** on a desktop-sized screen, a small card just above the lightbulb offers the App Tour. It is an offer, not a takeover, and the page stays usable behind it:

* **Start** begins the tour.
* **Not Now** hides the card until the browser tab is closed, and it is offered again next time. The tour stays in the lightbulb meanwhile.
* **Don't Ask Again** stops offering walkthroughs to you automatically, on every page.

The offer appears once per user: starting the tour, finishing it or stopping it all count as having seen it.

### Turning the offer back on

**Don't Ask Again** is a per-user setting. To change it, open your **User Profile**, check or clear **Offer Walkthroughs Automatically** under **Walkthroughs**, and save. Turning the offer off does not hide the lightbulb, so the tour stays available either way.

## What is stored

For each user and walkthrough, DefectDojo Pro stores whether the walkthrough was started or completed, the last step reached, and when it was started and last completed. It also stores each user's **Offer Walkthroughs Automatically** and **Show the Walkthrough Lightbulb** settings. Nothing is recorded about what you clicked or typed during a walkthrough.
