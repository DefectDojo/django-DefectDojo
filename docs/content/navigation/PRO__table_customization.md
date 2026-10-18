---
title: "Customizing Tables"
description: "Filter, sort, choose, reorder, resize, and save the columns on DefectDojo Pro data tables, and switch between the table and the grid"
weight: 8
---

Most data tables in the DefectDojo Pro UI (Findings, Assets, Engagements, and the other list views) can be tailored to how you work. You can choose which columns are visible, reorder them, adjust their widths, and save any combination as a named table preference that you can switch between or share with your team.

All of these controls live in the table toolbar, above the list.

## Filtering with the filter bar

The Findings list carries a filter bar between the toolbar and the rows. It shows every active filter as a chip that reads as a sentence: the field, the operator, and the value, such as **Severity is any of Critical, High** or **Age is greater than 30**.

- **Add Filter** opens a list of every field the table can filter on, grouped the way the column picker groups them. Type in the search box to narrow the list, then pick a field to open its editor. The editor is the same control the column header offers for that field: a match mode where the field has one, a value or a list of values, and **Submit** and **Clear**. Pressing Enter submits the editor from the same fields that apply a column header filter (see [Filtering columns](#filtering-columns)).
- Select a chip to reopen its editor and change the value or the match mode. Select the **x** on a chip to remove that filter.
- The count on the right of the bar is how many records match. **Sort** beside it opens the same sort the column headers offer, up to three levels, so a view with no headers (the grid, below) can still be ordered.
- The keyword search stays in the toolbar. It narrows the list on top of the chips and is not a chip itself.
- **Clear Filters** in the toolbar removes every chip, resets the match mode (below), and clears the keyword search.

The column header filters keep working. A filter applied from a header appears as a chip, and a chip removed from the bar clears the header, because both edit the same filters. Filters set through the bar are part of the page URL, so a bookmarked or shared link opens the list filtered the same way.

### Matching all filters or any filter

With two or more chips, the word between them is the connective. It reads **and** by default: a record must match every filter. Select it to switch the list to **or**, drawn in the accent color: a record matches when it satisfies at least one filter. Select it again to go back to **and**.

Three things never join the **or** group, because they define the page rather than narrow it: the context a page arrives with (the asset whose findings you are looking at, or the status a status page lists), the keyword search, and your own permissions. A context the page sets as a filter, such as **Status is any of Active** on the Active Findings page, shows as a locked chip ahead of the connective; it has no remove button, and the connective only joins the filters you add. A list in **or** mode can never show a record you could not see with no filters at all.

The match mode is part of the page URL and of a saved table preference, so a shared link or a shared preference opens in the mode it was saved in. Exports started from the table use the same mode as the rows on screen.

## Switching between the table and the grid

The Findings list can be read as a table or as a grid of cards. The two buttons beside the keyword search switch between them. The grid shows the same page of records, under the same filters, sort, and keyword search, so switching never changes what the list contains, only how each record is drawn.

A card shows the finding's severity, status, and title, where it lives (organization, asset, engagement, and test), its scores (CVSS, EPSS, priority, age, SLA, and CWE), the signals that matter when they apply (known exploited, ransomware, exploit maturity, reachability, a Sensei fix, a Jira issue, connector tickets), its tags and vulnerability ids, and a footer with the date found, the scanner, and the other dates and people on it. A card omits what is empty: a finding that is not in KEV and has no tags does not spend lines on them. The first two lines of the description appear as a summary when the comfortable density is on.

- The **Columns** button becomes **Fields** in the grid. It is the same selection in both views: the columns chosen for the table are the fields a card shows, and a field only a card can show (the summary) is offered in the grid.
- The density toggle applies to cards too: compact cards are smaller and fit one more per row.
- Select a card's checkbox to select it; the bulk actions appear above the grid as they do above the table, and the checkbox at the start of the filter bar selects every card on the page.
- The view is remembered per table in your browser and is part of the page URL (`view=grid`), so a shared link opens in the view it was shared from. On a phone-sized screen a first visit opens the grid.

## Choosing which columns are visible

Select the **Columns** button in the toolbar to open the column picker, then check or uncheck a column to show or hide it. Use the search box at the top of the picker to find a column by its header. A few structural columns (the selection checkbox and the row-action menu) are always present and are not listed in the picker.

The checkbox beside the search box selects or clears every listed column in one click. It works the same way as the select-all checkbox in a column filter, and it is checked when every listed column is shown. To build a narrow view, clear the checkbox so no columns are shown, then check only the columns you want. If only some columns are shown, the first click selects them all and the second clears them. When the search box holds text, the checkbox applies only to the columns that match the search: search for "date" and check it to add every date column. Columns hidden by the search keep their current state.

## Sorting columns

Click a column header to sort the table by that column. The first click on a number, score, or date column (such as EPSS Score, CVSS, Risk, a finding count, or Created) sorts it highest or newest first. The first click on a text column (such as Title or Status) sorts it A to Z. Click the same header again to reverse the direction, and a third time to clear that sort.

Rows with no value in the sorted column always appear at the end, whichever direction you sort in, so a "highest first" sort starts with real values rather than blanks.

To sort by more than one column, hold Ctrl (Cmd on macOS) while clicking additional headers. Each header shows its position in the sort. The sort is part of the page URL, so a bookmarked or shared link opens the table sorted the same way.

## Filtering columns

Click the filter icon in a column header to open that column's filter. Enter a value, pick a date, or check the options you want, then click **Apply** or press Enter. Enter applies the filter from a text or number field, from a typed date, and from a multi-select option list. In an option list, Space checks or unchecks the highlighted option and Enter applies the filter. In an "is one of" list, the first Enter adds the typed value to the list and a second Enter applies the filter. On the calendar, Enter selects the highlighted day instead, so click **Apply** after picking a date there. Pressing Enter while **Clear** has focus clears the filter instead.

## Reordering columns

Drag a column header left or right to move that column. The new order takes effect immediately for the current session.

## Resizing columns

Hover over the right edge of any data column's header until the resize cursor appears, then drag to make the column wider or narrower.

Two things to keep in mind:

- Each column has a minimum width, set so its title, sort arrow, and filter icon always stay readable. You can widen a column freely, but you cannot drag it narrower than that minimum.
- The selection and row-menu columns are fixed and cannot be resized.

Like column order and visibility, a width change applies to the current session until you save it (see below).

## Saving table preferences

Column visibility, column order, column widths, page size, filters, sort order, the match mode of the filter bar, and the view (table or grid) can be saved together as a named table preference. A preference that was saved in the grid opens in the grid; one saved in the table opens in the table. Open the preferences menu from the toolbar (the button showing the active view's name) to manage them.

- **Save as New Preference**: capture the current table setup under a new name. You can optionally set it as your default and, if you have permission, share it with other users.
- **Save Column Layout**: update the active preference's columns only (visibility, order, widths, page size, and the view), leaving its saved filters and sort untouched.
- **Save Filters and Sort**: update the active preference's filters, sort, and match mode only, leaving its column layout untouched.
- **Set Preference as Default**: load this preference automatically whenever you open the table.
- **Duplicate Preference**: copy the active preference (including its column widths) to a new name so you can adjust it without changing the original.
- **Update Preference Label**: rename the active preference.
- **Delete Preference**: remove the active preference.
- **Reset All Preferences**: remove every saved preference for this table and return to the built-in defaults.

### Unsaved changes

When you change a table's columns, filters, or sort order, a dot appears on the corner of the preferences menu button to show that the table no longer matches the active preference (or the built-in defaults) and can be saved. Open the menu to see what changed: a note at the top names the column layout, the filters and sort order, or both, and the same dot marks each save action that would keep the changes. Saving clears the dot, and so does switching to a preference. Saving the column layout clears it only for the columns, and saving the filters and sort clears it only for those.

The dot compares against the table as it was when the page loaded or a preference was last applied or saved, so it does not follow you across a page reload. Filters carried in a link you opened count as part of that starting point.

To switch between preferences, pick one from the list in the preferences menu. Selecting **Default** returns the table to its built-in columns and widths without deleting any of your saved preferences.

Shared preferences created by other users appear under the **Shared Preferences** tab of the menu. You can load or set a shared preference as your default, but only its creator can change or delete it.

## Global defaults and restricted customization

An administrator can pin everyone to a shared table view instead of letting each person keep their own.

- **Set as Global Default**: on a shared preference, the preferences menu offers **Set as Global Default** to users who can share preferences. The designated preference becomes the one every user is shown for that table while customization is restricted. You can also choose it on the Layout Defaults settings page (Settings, then UI Defaults, then Layout Defaults), which offers a dropdown of the shared preferences for each table.
- **Restrict Layout Customization**: a system setting (Settings, then UI Defaults, then Layout Defaults) that, when enabled, limits table customization to superusers. Everyone else is shown the designated global default for each table, or the table's built-in columns when none is designated, and the **Views** and **Columns** buttons are hidden. Sorting, filtering, and searching still work.

Personal preferences saved before the setting was enabled are not deleted. They are ignored while it is on, and they reappear if an administrator turns it back off.
