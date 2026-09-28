---
title: "Configuring Forms"
description: "Choose which fields the DefectDojo Pro create and edit forms show, which are required, and the order they appear in"
draft: false
weight: 10
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Form Configuration is a DefectDojo Pro feature, and is available to administrators from **Settings > UI Defaults > Form Configuration**.</span>

The create and edit forms in DefectDojo Pro ship with a sensible set of fields, but not every organization collects the same information. Form Configuration lets an administrator decide, per form, which fields appear, which are mandatory, where they sit, and what order they come in.

**This is an instance-wide setting, not a personal preference.** Changes apply to everyone, and each person picks them up the next time they navigate to a new page.

## Choosing a form

Pick the form you want to change from the selector at the top of the page. Each entity that has a create and edit form has an entry, for example the Finding form and the Asset form. The rest of the page then shows that form's fields.

## The field list

Fields are listed one per row, with a **State** column describing what you can do with each. A field falls into one of three cases:

- **Not Configurable**: the form needs this field to work, so it cannot be moved, hidden, or made optional. It is still listed so you can see the form's full shape.
- **Always Required**: the field is mandatory and stays that way, though you can still change where it appears in the order.
- **Configurable**: the field offers the controls below.

For a configurable field you can set:

- **Placement**, either **Main** or **Optional**. Main puts the field in the body of the form, where it is visible as soon as the form opens. Optional moves it into the collapsible Optional Fields section.
- **Required**, which makes the field mandatory. Someone filling in the form cannot submit it until the field has a value.
- **Disabled**, which takes the field off the form entirely.

## Custom fields

If [Custom Fields](../../asset_modelling/pro__custom_fields/) is enabled, the fields defined for a
form's record type are listed here too, marked **Custom Field**, and configure exactly like the
built-in ones. They start in the Optional Fields section, so this page is where you promote one into
the body of the form, hide it, require it, or move it in the order.

A custom field defined as required carries **Always Required**: it cannot be hidden or made optional
here, though you can still change where it appears. Requiring a custom field on this page instead
makes it mandatory on this form only, leaving the same field optional elsewhere.

Only forms whose records can carry custom fields list them: Organizations, Assets, Engagements, Tests,
Findings, and Risk Acceptances. The Import Scan, Reimport Scan, and JIRA Instance forms do not.

## Changing the order

Drag the handle at the left of a row to change the order fields render in. This controls the sequence only. Whether a field sits in the body of the form or in Optional Fields is still governed by its Placement setting, so reordering a field will not move it between the two sections.

You can reorder a field that is otherwise not configurable, because its position still affects how the form reads.

## Optional Fields on open

**Expand Optional Fields by Default** decides whether the Optional Fields section starts open or closed when someone opens one of these forms. Turn it on when most of your fields live in Optional Fields and you would rather people saw them without an extra click.

## Saving

**Save** applies your changes for everyone. **Reset to Defaults** returns the selected form to the configuration DefectDojo ships with, which is a good way back if a form has been narrowed too far.

Each form is saved separately, so resetting one leaves your changes to the others alone.
