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
- **Your Layouts**: layouts you have created.
- **Shared Templates**: layouts someone has published for everyone on the instance.

## The Page Layout menu

Every one of the six pages has a **Page Layout** button in its toolbar. Opening it lists the layouts available for that page, with the current one marked, and offers:

- **Edit Layout**: enter edit mode on the layout you are viewing.
- **New Layout**: create a layout from scratch or from an existing one.
- **Manage Layouts**: open the full management dialog.

Layouts in the list carry a marker showing where they came from: shipped with DefectDojo, a shared template, or your default.

## Making your first change

The shipped layouts are read only, so the first time you customize a page DefectDojo offers to make you a copy to work in. A **Create Your Own Layout** prompt appears, you give the layout a name, and **Create and Edit** puts you straight into edit mode on your new copy. The shipped layout is left untouched, so you can always go back to it.

## Editing a layout

In edit mode:

- **Move a widget** by dragging it.
- **Resize a widget** by dragging its edge. The grid has twelve columns, and widgets snap to them.
- **Configure Widget** opens the widget's own settings. What is on offer depends on the widget: which columns a table shows, which fields a panel lists, what a chart plots, and so on. You can also retitle a widget here.
- **Remove Widget** takes it off the layout. You can add it back later.
- **Add Widget** opens the catalog of widgets available for that page.

**Your changes are saved as you go.** There is no separate save step. **Done** leaves edit mode, and anything you changed is already stored.

## Creating a layout from scratch

**New Layout** asks for a **Layout Name** and a **Start From** choice, so you can begin from the shipped layout, from one of your own, or from a shared template. Starting from an existing layout copies it, and the original is unaffected.

## Managing layouts

**Manage Layouts** lists every layout for the page under the three headings above, and offers:

| Action | What it does |
| --- | --- |
| **Use Layout** | Switch to that layout. |
| **Rename** | Change a layout's name. |
| **Clone** | Copy a layout, including a shared or shipped one, into Your Layouts. |
| **Delete** | Remove one of your layouts. |
| **Set Default** / **Clear Default** | Choose which layout you personally land on for this page. |
| **Share** / **Unshare** | Publish one of your layouts as a shared template, or withdraw it. |
| **Set Shared Default** / **Clear Shared Default** | Choose which layout everyone on the instance lands on for this page. |

Sharing a layout and setting the instance-wide default require the **Page Layout Share** permission, which Maintainer and Owner hold by default. If you do not have it, the sharing controls are not shown. Publishing a shared template applies to the whole instance, not to a single Organization.

## Which layout you see

When you open one of the six pages, DefectDojo picks the first of these that applies:

1. The layout you last chose for that page.
2. Your personal default, if you have set one.
3. The instance-wide shared default, if an administrator has set one.
4. The layout shipped with DefectDojo.

## Widgets with nothing to show

A widget is left out of the page when it has nothing to display, for example a tab for a feature that is turned off, or a table for a record that has no rows. The remaining widgets close the gap, so you do not get holes in the page.

This affects only what is drawn. Your layout is unchanged, and the widget reappears when there is something in it.

In edit mode those widgets are shown as labelled placeholders that say why they are not appearing, so you can still position them.

## When customization is restricted

An administrator can turn on **Restrict Layout Customization** in **Settings > UI Defaults > Layout Defaults**. With it on:

- Only superusers can create or change layouts.
- Everyone else sees the layout designated as the default, or the shipped layout when none has been designated.
- The Page Layout menu no longer offers the editing and management actions.

Layouts you saved before the switch was turned on are kept. If it is turned back off, they are available again exactly as they were.

For the administrator's side of this, see [The Sidebar Menu](/navigation/pro__sidebar/).

## The widget catalog

Which widgets a page offers depends on the page, and **Add Widget** shows what is available with a short description of each. Widgets come in four shapes:

- **Panels** present the record's own fields as a list of labelled values.
- **Tables** list related records, such as the Engagements on an Asset or the Findings on a Test. These behave like the product's other data tables, so you can pick columns and sort them.
- **Feeds** present a running history in date order, such as notes on a record.
- **Charts** plot the record's data, such as severity breakdowns and counts over time.

Some widgets appear only when the feature behind them is available to you. For example, the **Automation History** widget on the Asset and Finding pages shows what the rules engine did to that record and why, so it is offered only when Rules Engine 2.0 is turned on and you hold Rule View.
