---
title: "In-App Walkthroughs"
description: "Guided, step-by-step tours and tasks in the DefectDojo Pro UI: the App Tour, the tours for each area, the task walkthroughs for everyday work, administration, Jira and the Triage Engine, the first-visit offer, and turning the offer off per user"
weight: 9
audience: pro
---

A walkthrough guides you through the Pro UI one area at a time. Each step outlines part of the page and dims everything else, and a small card beside the outline says what the area is for. Only the outlined area and the card respond to clicks while a step is showing, so nothing else on the page can be changed by accident.

Where there is more to read, the card has a **Learn more** link to the matching part of this documentation. It opens in a new tab, so the walkthrough stays where it is.

Some steps move on when you select **Next**. Others move on when you do the real thing, such as opening a menu or a record, and the card says which. The walkthrough never clicks anything for you.

## The Documentation link

A page that has its own documentation shows a **Documentation** button at the top right, beside the bar that shows the page's location (the breadcrumbs). It opens the matching page of this documentation in a new tab. On a narrower screen, such as a phone or a small tablet, the button is the book icon alone.

The button is in the same place on every page that has one: the deduplication settings (**Matching Configuration** and **Dedupe Pools**), the connector pages, the single sign-on and login settings, notifications, SLAs, custom fields, layouts and form configuration, the PSIRT settings, and **Settings > Feature Flags**. A page that belongs to a feature behind a flag links to the same documentation as that flag's entry on **Settings > Feature Flags**, so turning a feature on puts its documentation one click from every page it adds.

## The lightbulb

A yellow lightbulb in the lower right corner of every page opens the list of walkthroughs. Walkthroughs made for the page you are on come first, under **This Page**, followed by the ones you can take from anywhere, under **General**. Each entry reads **Take the Tour**, **Resume Tour** or **Retake the Tour**, depending on how far you got last time.

The list only ever holds walkthroughs for features you can use. A walkthrough for a feature that is turned off on your instance, or that your role does not give you access to, does not appear in the lightbulb at all, and it is never offered to you.

**All Walkthroughs**, at the top of the list, opens every walkthrough you can take in one table, not just the ones for this page. Each row shows whether you have not started it, are part-way through, or have completed it, and its menu takes, resumes, retakes or restarts it.

A small dot on the lightbulb means a walkthrough in the list is one you have not seen yet. The lightbulb steps aside while a walkthrough is running, and it is not shown on phone-sized screens.

To hide the lightbulb, open it and click **Hide Walkthroughs** at the bottom of the list. The lightbulb goes away at once, on every page, and a message links to your **User Profile**, where you can turn it back on. To hide or show it from the profile instead, clear or check **Show the Walkthrough Lightbulb** under **Walkthroughs**, and save. Hiding the lightbulb does not stop the first-visit offer; turn that off separately (see [Turning the offer back on](#turning-the-offer-back-on)).

## Turning walkthroughs on

Walkthroughs are on for every instance, Cloud and On-Premise, and there is nothing to enable. Each user decides for themselves whether walkthroughs are offered automatically and whether the lightbulb shows, as described above and under [Turning the offer back on](#turning-the-offer-back-on).

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
| **Keep an Upstream Connector Running** | The Upstream connector, records and connection settings pages | A connector's health, every run it made and why one failed, where else problems show, changing its schedule, and the notification that says when it breaks | Users who can view connectors. The schedule steps need permission to change connectors |
| **Dedupe Pools** | Dedupe Pools and Matching Configuration | How a pool lets Findings deduplicate across Assets, where the originals collect, and how Matching Configuration fits in | Users who can view Dedupe Pools. The steps that add or change a pool need permission to add or change pools |
| **SAML Settings, Field by Field** | The SAML settings page and Authorization | The URLs to give the identity provider, the fields that decide which account a login lands on, group mapping, and checking the settings with **Validate Config** | Users who can view identity providers. The steps that change a setting need permission to change them |
| **OIDC Settings, Field by Field** | The OIDC settings page and Authorization | The endpoint, the client and the redirect URI to register at the provider, which account a login lands on, group mapping, and checking the settings with **Validate Config** | Users who can view identity providers. The steps that change a setting need permission to change them |
| **Where Access Comes From** | A user's page | How roles on Organizations, Assets and groups, a global role and configuration permissions add up to what a user can reach, and where each one is changed | Users who can view other users |
| **Read Triage Engine Runs** | The Triage Engine Runs and Deliveries pages | A run and its node trace, the Findings it changed and left alone, why an errored run changed nothing, a rule's deliveries and why one was skipped or failed, its payload, and the Automation History a run leaves on a Finding | Users with a global role that can view rules, when the Triage Engine is turned on |

## Task walkthroughs

A task walkthrough goes one step further than a tour: you do the job for real while it guides you, and what you create or change stays. Each step outlines the control to use, the card says what it does, and the walkthrough moves on when the action has actually succeeded, such as when a form is saved or a record opens. If the action fails, the walkthrough waits on the same step until it works.

Because a task changes real data, it practices on the record you started it from when it can, and otherwise on the least important one it finds, such as the lowest-severity active Finding. Its last card says how to undo what it did. The [sandbox](/admin/sandbox/pro__sandbox/) is a good place to try one first.

A few things work differently from a tour:

* The lightbulb entry reads **Start**, **Resume**, **Do It Again** or **Start Over**.
* Stopping asks first. The **X** on the card, or the **Escape** key, asks whether to stop; the progress made so far is kept either way.
* A task does not pick up again on another page if one of its steps could not be found. Start it again from the lightbulb.

Some tasks set up a connection to another system, such as a Jira site or a scanner. Those need that system's details to hand (a URL and credentials), and the walkthrough waits on the step that asks for them.

| Task | Start it from | What you do | Who sees it |
|---|---|---|---|
| **Import and Reimport a Scan** | The Import page and a Test | Import a scan into a new Test, read its Import History, then reimport a newer scan into the same Test and read what changed | Users who can import scan results |
| **Create an Asset and Import Into It** (or Create a Product and Import Into It) | The Organizations list | Open or create an Organization, add an Asset in it, add an Engagement in that, and import a first scan, each from the gear menu of the level above | Users who can add Assets to an Organization. The import steps need permission to import scan results |
| **Add an Engagement and Import Into It** | An Asset | Add an Engagement to an existing Asset from its gear menu, then import a first scan into it, for users who cannot create Assets | Users who can add Engagements. The import steps need permission to import scan results |
| **Mark a Finding a False Positive** | A Finding | Close the Finding as a false positive with the note it needs, and see what keeps it a false positive on later imports | Users who can edit Findings |
| **Accept the Risk of a Finding** | A Finding | Add a full risk acceptance with its owner, decision and expiry, see what happens when it expires, find the Finding on Risk Accepted Findings, and, where the Asset allows it, where simple risk acceptance is set instead | Users who can edit Findings and add risk acceptances |
| **Close Findings in Bulk** | Every Findings status list | Filter the list, save the view, select the page, and close the Findings on it with one Bulk Edit and a note | Users who can edit Findings. The view step is skipped when page layouts are locked |
| **Give a User Access to an Asset** (or a Product) | An Asset and an Organization | Open Permissions from the gear menu, add a user with a role, find their row, see where groups are added, and what a role on an Asset or an Organization covers | Users who can manage an Asset's members. The groups step needs permission to add groups |
| **Build and Generate a Report** | The report templates list | Create a template with a new block, choose the block's fields and filters, save both, generate a report, and find it on Generated Reports | Users with a global role that can add report templates and generate reports, when Reporting is turned on |
| **Set Up an Upstream Connector** | The Upstream connector and records pages | Add a connector for a scanner or security tool with its credentials and schedules, run its first Discover, map the records it found to Assets, and Sync | Users with a global role that can view and change connectors |
| **Add a User** | The user lists and the New User form | Create a user, and see why a new user reaches nothing until given a role | Users who can add users |
| **Set Up a Group** | The groups list and the New Group form | Create a group, add its members from its Permissions dialog, and see why a group reaches nothing until it holds a role on an Asset or an Organization | Users who can add groups |
| **Move to Locations** | Feature Flags and the Endpoints pages | Turn Locations on and carry existing endpoint history forward with the data migrations, with what cannot be undone | Superusers |
| **Set Up the Jira Connector** | The Downstream connector pages | Connect a Jira site, map Findings to a Jira project and issue type, and assign the mapping to an Asset or an Engagement so its Findings can be pushed | Users with a global role that can view and change integrations, when Downstream connectors are turned on |
| **Push a Finding to Jira** | A Finding | Send a Finding through the Jira connector, read what the push did, and find its ticket on the Finding and in the Findings lists | Superusers, when Downstream connectors are turned on |
| **Turn On Jira Two-Way Sync** | The Jira connections, Webhook Receivers and a receiver's page | Create a webhook receiver for the Jira connection, create the matching webhook in Jira, and see where deliveries and the rule that acts on them show | Users with a global role that can view integrations and view and add rules, when Downstream connectors, the Triage Engine and inbound webhooks are turned on |
| **Build a Rule That Tags Findings** | The Triage Engine rules list and rule editor | Build a rule that tags new High and Critical Findings: a trigger, an If / Filter on severity and an Add Tags node, connected on the canvas and previewed before it is saved | Users with a global role that can view and add rules, when the Triage Engine is turned on |
| **Run a Triage Engine Rule** | The Triage Engine rules list and rule editor | Open a rule you own, read its trigger, enable and save it, select **Run Now**, read the run it produced, and see how a schedule or an import starts it instead | Users with a global role that can view and change rules, when the Triage Engine is turned on. It needs a rule you own that is not started by a webhook |

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
