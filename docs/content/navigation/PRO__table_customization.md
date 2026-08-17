---
title: "Customizing Tables"
description: "Choose, reorder, resize, and save the columns on DefectDojo Pro data tables"
weight: 8
---

Most data tables in the DefectDojo Pro UI (Findings, Assets, Engagements, and the other list views) can be tailored to how you work. You can choose which columns are visible, reorder them, adjust their widths, and save any combination as a named table preference that you can switch between or share with your team.

All of these controls live in the table toolbar, above the list.

## Choosing which columns are visible

Select the **Columns** button in the toolbar to open the column picker, then check or uncheck a column to show or hide it. Use the search box at the top of the picker to find a column by its header. A few structural columns (the selection checkbox and the row-action menu) are always present and are not listed in the picker.

## Reordering columns

Drag a column header left or right to move that column. The new order takes effect immediately for the current session.

## Resizing columns

Hover over the right edge of any data column's header until the resize cursor appears, then drag to make the column wider or narrower.

Two things to keep in mind:

- Each column has a minimum width, set so its title, sort arrow, and filter icon always stay readable. You can widen a column freely, but you cannot drag it narrower than that minimum.
- The selection and row-menu columns are fixed and cannot be resized.

Like column order and visibility, a width change applies to the current session until you save it (see below).

## Saving table preferences

Column visibility, column order, column widths, page size, filters, and sort order can be saved together as a named table preference. Open the preferences menu from the toolbar (the button showing the active view's name) to manage them.

- **Save as New Preference**: capture the current table setup under a new name. You can optionally set it as your default and, if you have permission, share it with other users.
- **Save Column Layout**: update the active preference's columns only (visibility, order, widths, and page size), leaving its saved filters and sort untouched.
- **Save Filters and Sort**: update the active preference's filters and sort only, leaving its column layout untouched.
- **Set Preference as Default**: load this preference automatically whenever you open the table.
- **Duplicate Preference**: copy the active preference (including its column widths) to a new name so you can adjust it without changing the original.
- **Update Preference Label**: rename the active preference.
- **Delete Preference**: remove the active preference.
- **Reset All Preferences**: remove every saved preference for this table and return to the built-in defaults.

To switch between preferences, pick one from the list in the preferences menu. Selecting **Default** returns the table to its built-in columns and widths without deleting any of your saved preferences.

Shared preferences created by other users appear under the **Shared Preferences** tab of the menu. You can load or set a shared preference as your default, but only its creator can change or delete it.
