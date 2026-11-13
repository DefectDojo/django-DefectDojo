---
title: "Customizing Page Layouts"
description: "Arrange the widgets on DefectDojo Pro view pages, then save, share, or set a layout as the default"
draft: false
weight: 9
audience: pro
aliases:
  - /pro/page_layouts/
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Customizable Page Layouts are a DefectDojo Pro feature. Layout customization is available by default. An administrator can restrict it so that everyone sees a standard layout: see [When customization is restricted](#when-customization-is-restricted).</span>

Six view pages in DefectDojo Pro are built from widgets arranged on a grid, and you can rearrange them to suit how you work:

- Organization
- Asset
- Engagement
- Test
- Finding
- Risk Acceptance

Every panel, table, chart, and tab strip on those pages is a widget. You can move it, resize it, retitle it, configure it, remove it, or add one that is not currently shown.

## What a layout is

A **layout** is a saved arrangement of widgets for one page type. A layout you build for the Asset page applies to every Asset you open, not to one particular Asset.

Layouts come from three places:

- **Shipped With DefectDojo**: a built-in layout for each of the six pages. This is what you see before you change anything.
- **Saved Layouts**: layouts you have created.
- **Shared Templates**: layouts someone has published for everyone on the instance.

## The Page Layout menu

Every one of the six pages has a **Page Layout** button in its toolbar. Opening it lists the layouts available for that page, with the current one marked, and offers:

- **Edit Layout**: enter edit mode on the layout you are viewing.
- **New Layout**: create a layout from scratch or from an existing one.
- **Manage Layouts**: open the full management dialog.

Layouts in the list carry a marker showing where they came from: shipped with DefectDojo, a shared template, or your **My Default**.

## Making your first change

The shipped layouts are read only, so the first time you customize a page DefectDojo offers to make you a copy to work in. A **Create a Personal Layout** prompt appears, you give the layout a name, and **Create and Edit** puts you straight into edit mode on your new copy. The shipped layout is left untouched, so you can always go back to it.

## Editing a layout

In edit mode:

- **Move a widget** by dragging it.
- **Resize a widget** by dragging its edge. The grid has twelve columns, and widgets snap to them. A Simple Table with a flat list of chosen fields cannot be made shorter than the height those fields need on one line each (rows that hide when they are empty aside), and one saved shorter than that is shown at that height, together with the widgets of the same height in its row so the row stays level. A Simple Table with groups has no such floor: its groups fold, and its list scrolls inside the tile. A Field widget is at least two rows tall, so its value shows under its title, and one saved shorter is shown at two rows in the same way. Other widgets keep the height you give them.
- **Configure Widget** opens the widget's own settings. What is on offer depends on the widget: which columns a table shows, which fields a panel lists, what a chart plots, and so on. You can also retitle a widget here.
- **Remove Widget** takes it off the layout. You can add it back later.
- **Add Widget** opens the catalog of widgets available for that page.

**Your changes are saved as you go.** There is no separate save step. **Done Editing** leaves edit mode, and anything you changed is already stored.

## Creating a layout from scratch

**New Layout** asks for a **Layout Name** and a **Start From** choice, so you can begin from the shipped layout, from one of your own, or from a shared template. Starting from an existing layout copies it, and the original is unaffected.

## Managing layouts

**Manage Layouts** lists every layout for the page under the three headings above, plus **Group Layouts** (the page's layouts your Groups own or were given), and each row's menu offers:

| Action | What it does |
| --- | --- |
| **Use Layout** | Switch to that layout. |
| **Rename** | Change a layout's name. |
| **Clone** | Copy a layout, including a shared or shipped one, into Saved Layouts. |
| **Delete** | Remove one of your layouts. |
| **Set as My Default** / **Clear My Default** | Choose which layout you personally land on for this page. The layout carries a **My Default** tag. |
| **Share** | Set who can see a layout: **Only Me**, **Specific Groups** (they can use it but not change it), or **Everyone** (a shared template). Without Group Ownership on, this is **Share** / **Unshare**: publish a layout as a shared template, or withdraw it. |
| **Transfer** | Move a layout into a Group, or back to you. Members whose role in the Group carries **Page Layout Share** manage a Group's layouts; every other Member uses them as they are. |
| **Set as Instance Default** / **Clear Instance Default** | Choose which layout everyone on the instance lands on for this page. A layout from a Default Profile reads **From <profile>**, or **Set by <profile>** when it is locked. |

Publishing to everyone and setting the Instance Default require the **Page Layout Share** permission, which Maintainer and Owner hold by default. If you do not have it, the sharing controls are not shown. Publishing a shared template applies to the whole instance, not to a single Organization.

## Which layout you see

When you open one of the six pages, DefectDojo picks the first of these that applies:

1. The layout you last chose for that page.
2. Your own default (**My Default**), if you have set one.
3. The layout from a [Default Profile](/admin/user_management/create_user_group/#defaults): the one assigned to you directly, else your Groups' profiles in rank order (the first that sets one wins).
4. The **Instance Default**, if an administrator has set one.
5. The layout shipped with DefectDojo.

## Fields you can change in place

On the Finding, Engagement and Asset pages, a field tile or a row of the details table can be changed where it sits when the field supports it and you can edit the record: the value is highlighted on hover, and a click opens its editor. On a Finding that is Severity, Assignees, Planned Remediation Date and Description; on an Engagement, Status, Lead, Start Date, End Date and Description; on an Asset, Business Criticality, Platform, Lifecycle and Description. Moving or resizing the widget does not change this. See [Change a Field in Place](/triage_findings/findings_workflows/editing_findings/#change-a-field-in-place).

## Grouping the fields of a Simple Table

A Simple Table (the **Details** table on each View page) lists the record's fields one per line, with the label on the left and the value on the right. A value too long for its line ends in an ellipsis: hover over it, or move to it with the keyboard, to read all of it.

The fields can sit under named headers, and each header folds its group away. To set them up:

1. In edit mode, open **Configure Widget** on the table.
2. Under **Fields**, choose the fields the table shows and drag them into order.
3. Under **Groups**, click **Add Group** and type its name. Add as many groups as you need, and use the arrows to put them in order, or the delete button to remove one (its fields stay in the table, ungrouped).
4. Under **Field Groups**, pick each field's group. A field in no group shows at the top of the table, with no header. Inside a group, fields keep the order they have under **Fields**.
5. To keep custom fields showing that no group names, including ones added later, tick **Show Other Custom Fields**: they show under a **Custom Fields** header at the end.
6. Click **Submit**.

The field list offers every field the page has, whatever record you edit the layout from: the Jira and connector fields, for example, are on offer whenever Jira or connectors are turned on, even when the record open at the time has no ticket. On a record without a value for one of them, its row is left out.

On the page, each group's header shows its name and counts the fields it shows for that record, so a field left out because it is empty or does not apply is not counted. Select it, or press Enter or Space on it, to fold the group to its header or to open it again. Which groups you fold is remembered for you and for that table only: it does not change the layout, the record or what anyone else sees. In a wide table the groups flow into columns; in a narrow one the label sits above its value.

The default layouts already group the larger tables, for example the Finding's **Details** table into **Triage**, **Ownership and Plan**, **Where Found**, **Scores and Intel** and **Tracking**.

## Widgets with nothing to show

A widget is left out of the page when it has nothing to display, for example a tab for a feature that is turned off, or a table for a record that has no rows. The remaining widgets close the gap, so you do not get holes in the page.

This affects only what is drawn. Your layout is unchanged, and the widget reappears when there is something in it.

In edit mode those widgets are shown as labelled placeholders that say why they are not appearing, so you can still position them.

### Hiding empty tabs

A tab that holds a list, such as a table, Notes or Files, shows how many items it has beside its label, and a tab with none is dimmed, so an empty tab reads as empty before you open it.

Some tabs in a tab group always show, even when they are empty, such as a table with no rows or a Notes feed with no notes. You can choose to hide them on records where they have nothing to show, one tab at a time:

1. In edit mode, open **Configure Widget** on the tab group.
2. Each tab's row has an eye button beside its delete button. Click it to switch between the open eye (the tab always shows) and the crossed-out eye (the tab is hidden when it is empty). Hover over the button to see what a click will do.
3. Click **Submit**.

Leave the eye open on a tab whose own button adds its first item, such as Notes or Files: hiding an empty Notes tab also hides **Add Note**.

The eye is locked in two cases, and hovering over it says why:

- **Crossed out and locked**: the tab already hides itself when it has nothing to show.
- **Open and locked**: the tab cannot tell when it is empty (some charts and composite panels), so it always shows.

A hidden tab comes back as soon as the record has something for it, the next time the page loads. In edit mode every tab is shown, with a note on the ones that are hidden outside edit mode.

## When customization is restricted

An administrator can turn on **Restrict Layout Customization** in **Settings > Defaults > Instance Defaults** (the **Layout Customization** card). With it on:

- Only superusers can create or change layouts.
- Everyone else sees the Instance Default layout, or the shipped layout when none has been set.
- The Page Layout menu no longer offers the editing and management actions.

Layouts you saved before the switch was turned on are kept. If it is turned back off, they are available again exactly as they were.

A [Default Profile](/admin/user_management/create_user_group/#defaults) can override the switch for its Members (its Groups' Members and users it is assigned to directly) in either direction, with **Allow** or **Restrict to Selected Layouts**. The first profile in the resolution order that sets it decides. A profile can also set the layout each View page opens with, and under **Restrict to Selected Layouts** list the other layouts Members may switch to; the layout switcher then offers only those, with no edit menu. Superusers are never restricted.

For the administrator's side of this, see [The Sidebar Menu](/navigation/pro__sidebar/).

## The widget catalog

Which widgets a page offers depends on the page, and **Add Widget** shows what is available with a short description of each. Widgets come in four shapes:

- **Panels** present the record's own fields as a list of labelled values, optionally under named groups (see [Grouping the fields of a Simple Table](#grouping-the-fields-of-a-simple-table)).
- **Tables** list related records, such as the Engagements on an Asset or the Findings on a Test. Most behave like the product's other data tables, so you can pick columns and sort them.
  The **Finding Groups** table on a Test is built to fit its tile. It keeps search, filters, sorting and your saved preferences (the filters and sort open from its **Filters** button), and shows a fixed set of columns: each group's severity, name, findings, SLA, status, tickets (its Jira issue and connector tickets) and creator. The creator gives way as the tile narrows, then the status (when it is not Active) and the tickets move under the group's name, and a narrow tile shows each group on two lines with its SLA under the name. The tile's header counts the groups past their SLA; a mitigated group never counts.
  The **Engagements** table on an Asset is built to fit its tile instead. It keeps search, filters, sorting, export and your saved preferences (the filters and sort open from its **Filters** button), and shows a fixed set of columns: the engagement with its type, status, dates, lead and active findings. Lead and then dates give way as the tile narrows, and a narrow tile shows each engagement on two lines. The tile's header counts the open engagements past their end date, or the ones in progress when none is overdue.
  The **Tests** table on an Engagement is built the same way. It keeps search, filters, sorting and your saved preferences, and shows each test with its notes count, its test type, its import status in words (an import that failed shows in red), when it was last updated with its reimports, and its active and total findings. Updated and total findings give way as the tile narrows, then the test type moves under the test's name, and a narrow tile shows each test on two lines. The tile's header counts the tests whose import failed, or the ones still processing when none failed.
  The **Findings** table on a Test is built the same way. Its fixed columns are the finding's severity, its risk (when risk scoring is turned on), the finding with its notes count, status, SLA and age. Risk and then age give way as the tile narrows, and a narrow tile shows each finding on two lines, with its severity, status and SLA under the title. The tile's header counts the open findings past their SLA.
  The **Locations** table on a Finding (shown when Locations is turned on) is built the same way. It keeps New Location, Add Existing, search, filters, sorting, row selection with its bulk actions, and your saved preferences, and shows each location's type, the location with up to two of its tags, this finding's status there, its relationship, and its active and total findings in the finding's Asset. The findings and tags give way as the tile narrows, and a narrow tile shows each location on two lines: the location with this finding's status beside it, then its type and relationship. The tile's header counts the locations the finding is still active on.
  The Engagements, Tests, Findings and Locations tables show as many rows as their tile holds, so resizing the tile changes how many rows a page shows without changing your saved page size. In a tab group, and in the single column a narrow screen shows, a tile has no height of its own, so these tables show your saved page size there instead. The **Full Table** button in the toolbar shows the complete table inside the tile, with every column, the column picker and the page size; select it again to go back. Your choice is remembered for you and for that widget only: it does not change the Engagements, Tests, Findings or Locations pages, the layout, or what anyone else sees.
- **Feeds** present a running history in date order, such as notes on a record.
- **Charts** plot the record's data, such as severity breakdowns and counts over time.

Some widgets appear only when the feature behind them is available to you. For example, the **Automation History** widget on the Asset and Finding pages shows what the rules engine did to that record and why, so it is offered only when Triage Engine is turned on and you hold Rule View.

The record cards on the Asset page (**Organization Memberships**, **Asset Identity**, **Exposure** and **Regulatory**) and the **Member Assets** table at the top of the Organization page are widgets as well. The shipped Asset layout starts with the Open Finding Severity meter and places the cards after the Details row: Organization Memberships and Asset Identity side by side, then Exposure and Regulatory at full width. The shipped Organization layout places Member Assets first. A layout saved before the cards were widgets had them added above its own widgets, so nothing that was on the page went missing; one that was not rearranged since has them moved below its widgets, in the same arrangement as the shipped layout. Like any widget you can move, resize or remove them. Each one is shown only while the feature behind it is turned on.
