---
title: "Configuring Forms"
description: "Choose which fields the DefectDojo Pro create and edit forms show, which are required, and the order they appear in"
draft: false
weight: 10
audience: pro
---
<span style="background-color:rgba(242, 86, 29, 0.3)">Note: Form Configuration is a DefectDojo Pro feature, and is available to administrators from **Settings > UI Defaults > Form Configuration**.</span>

The create and edit forms in DefectDojo Pro ship with a sensible set of fields, but not every organization collects the same information. Form Configuration lets an administrator decide, per form, which fields appear, which are mandatory, where they sit, and what order they come in.

**This is an administrator setting, not a personal preference.** People cannot pick their own configuration, and a change reaches them the next time they navigate to a new page.

## Configurations and the default

An instance can hold several named Form Configurations. **Settings > UI Defaults > Form Configuration** lists them, and one of them can be marked **Default**: that is the configuration everyone's forms follow. The others reach no one's forms until they are made the default.

From a configuration's menu you can:

- **Edit Form Configuration**: open it to change its forms, as described below.
- **Rename**: give it a new name. Names are unique, ignoring case.
- **Duplicate**: make a copy with "(Copy)" after its name, which is not the default. Use it to prepare a change and switch over in one step.
- **Make Default**: make it the configuration everyone's forms follow. The previous default stays in the list.
- **Delete**: remove it. Deleting the default leaves the instance with no default, so every form returns to its stock layout until another configuration is made the default.

**New Form Configuration** creates an empty configuration and opens it. The first configuration an instance creates becomes the default; later ones do not.

An instance upgraded from a version with a single Form Configuration keeps its settings: they become the default configuration, named "Default".

## Default Profile and instance defaults

A [Default Profile](/admin/user_management/create_user_group/#defaults) can point its Members (the users it is assigned to directly and the Members of its Groups) at another configuration. A person's forms follow the configuration set by the first profile that sets one, in this order: the profile assigned to them directly, then their Groups' profiles in rank order. Profiles do not combine. Otherwise the **Default** configuration applies, else the stock forms. Deleting a configuration that a profile uses clears it from that profile, and the delete dialog names those profiles.

## Choosing a form

Open a configuration, then pick the form you want to change from the selector at the top of the page. Each entity that has a create and edit form has an entry, for example the Finding form and the Asset form. The rest of the page then shows that form's fields.

## The field list

Fields are listed one per row, with a **State** column describing what you can do with each. A field falls into one of three cases:

- **Not Configurable**: the form needs this field to work, so it cannot be moved, hidden, or made optional. It is still listed so you can see the form's full shape.
- **Always Required**: the field is mandatory and stays that way, though you can still change where it appears in the order.
- **Configurable**: the field offers the controls below.

For a configurable field you can set:

- **Placement**, either **Main** or **Optional**. Main puts the field in the body of the form, where it is visible as soon as the form opens. Optional moves it into the collapsible Optional Fields section.
- **Required**, which makes the field mandatory. Someone filling in the form cannot submit it until the field has a value.
- **Disabled**, which takes the field off the form entirely. The form still sends the field's default value. **Close Old Findings** on the Reimport form is on by default, so with it disabled, every Reimport closes old Findings. **Async Import** on both forms follows the instance's async import setting, and a large scan file is always processed in the background, so disabling it does not make imports synchronous. The settings page notes both beside their **Disabled** checkbox.

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

## Fields changed in place

The Finding, Engagement and Asset pages let some fields be changed where they are shown, without opening the Edit Finding, Edit Engagement or Edit Asset form (see [Change a Field in Place](/triage_findings/findings_workflows/editing_findings/#change-a-field-in-place)). The default Form Configuration governs those fields the same way: a field set to **Disabled** has no editor on the page, and a field set to **Required** cannot be saved empty there either.

## Data sent through the API

The default Form Configuration also governs records written through the REST API (`/api/v2/`), so a script or integration follows the same rules as someone filling in the form. This covers creating and updating Findings, Engagements, Tests, Assets (on both `/api/v2/products/` and `/api/v2/assets/`), Organizations (on both `/api/v2/product_types/` and `/api/v2/organizations/`), and Risk Acceptances.

- A field set to **Disabled** cannot be written: a request that includes it is refused with a `400` naming the field.
- A field set to **Required** must have a value. Creating a record without it, or replacing one with `PUT` without it, is refused with a `400` naming the field. A `PATCH` that leaves the field out keeps its current value; one that empties it is refused.
- A field the form shows only for one Engagement type is required only for that type. The CI/CD fields (Build ID, Commit Hash, Branch/Tag and the server fields) are required only on a CI/CD Engagement, and Test Strategy only on an Interactive one. A `PATCH` that changes an Engagement to that type is refused when the field has no value.

The same rules apply to the other API actions that write one of these fields:

- Adding tags to a Finding (`/api/v2/findings/{id}/tags/`) is refused when Tags is disabled. Removing tags (`/api/v2/findings/{id}/remove_tags/`) is refused when Tags is disabled, and also when Tags is required and the request would remove every tag.
- Merging Findings (`/api/v2/findings/merge/`) is refused when it would write a disabled field: setting tags on any Finding involved (the destination's or the merged Findings'), or turning on the option that copies the merged Findings' tags, references, vulnerability IDs or endpoints onto the destination.
- Updating several Assets at once (`bulk_update` on `/api/v2/assets/` and `/api/v2/products/`) follows the Asset form's rules for the fields the request sets. Its tags are only ever added, so it is refused when Tags is disabled but never for leaving Tags empty. Removing an Asset's parent (`remove_parent`) is refused when Parent is disabled or required.
- Uploading proof for a Risk Acceptance (`upload_proof`) is refused when Proof is disabled. Requesting a risk acceptance (`/api/v2/risk_acceptance/request/`) is refused when it sets a disabled field, such as the Expiration Date; the form's required fields do not apply to a request.
- Accepting risks by vulnerability ID (`accept_risks` on `/api/v2/engagements/{id}/`, `/api/v2/tests/{id}/` and `/api/v2/findings/`) creates Risk Acceptances, so it follows the Risk Acceptance form's disabled fields: it is refused when Accepted By or Decision Details is disabled (every item sends both, the justification becoming the Decision Details), and when an item sends an Expiration Date while that field is disabled.

The instance's API schema (`/api/v2/oa3/schema/`, shown in Swagger at `/api/v2/oa3/swagger-ui/`) follows the configuration too, for a signed-in user: disabled fields are left out of the request bodies and required fields are marked required. Anyone not signed in, and the schema published with each release, see the stock forms.

Scan imports and reimports are not affected, since a scan file cannot supply a field an administrator chose to require. Neither is the JIRA Instance API.

## Saving

**Save** stores your changes in the configuration you are editing; they apply to everyone when it is the default. **Reset to Defaults** returns the selected form to the configuration DefectDojo ships with, which is a good way back if a form has been narrowed too far.

Each form is saved separately, so resetting one leaves your changes to the others alone.
