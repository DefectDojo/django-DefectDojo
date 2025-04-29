---
title: "Tags"
description: "Use Tags to create a new slice of your data model"
draft: false
weight: 2
exclude_search: false
---

Tags are ideal for grouping objects in a manner that can be filtered out into smaller, more digestible chunks.  They can be used to denote status, or to create custom sets of Product Type, Products, Engagements or Findings across the data model.

In DefectDojo, tags are a first class citizen and are recognized as the facilitators
of organization within each level of the [data model](../Product_hierarchy).

Here is an example with a Product with two tags and four findings each with a single tag:

![High level example of usage with tags](images/tags-high-level-example.png)

### Tag Formats

Tags can be formatted in any of the following ways:
- StringWithNoSpaces
- string-with-hyphens
- string_with_underscores
- colons:acceptable

## Tag Management (Pro UI)

### Adding and Removing

Tags can be managed in the following ways:

1. **Creating or Editing new objects**

   When a new object is created or edited through the UI or API, there is a field for specifying
   the tags to be set on a given object.

   ![tag](images/tags_product.png)

2. **When Importing/Reimporting Findings**

  Tags are available on the Import/Reimport form, both in the UI and via the API.  When this form is submitted, the **Test** will be tagged with `[tag]` and `[daily-import]`.  If "Apply Tags to Findings" or "Apply Tags to Endpoints" is selected, those objects will also be tagged.  Tags provide an opportunity to append automation run details and tool information that may not be captured in the Test or Finding object directly. 

   ![tag](images/tags_importscan.png)

3. **Via Bulk Edit**

  When many Findings are selected from a table, you can use the Bulk Edit menu to change the associated Tags for many Findings simultaneously.  Note that this will replace all Finding-level Tags with the Tags specified; existing Finding Tags will be overwritten.

  ![bulk editing findings](images/Bulk_Editing_Findings.png)

  For more information, see our guide to [Bulk Editing Findings](/en/working_with_findings/findings_workflows/editing_findings/#bulk-edit-findings).


## Tag Management (Classic UI / OpenSource)

### Adding and Removing

Tags can be managed in the following ways:

1. Creating or Editing new objects

   When a new object is created or edited through the UI or API, there is a field for specifying
   the tags to be set on a given object. This field is a multiselect field that also has
   auto completion to make searching and adding existing tags a breeze. Here is what the field 
   looks like on the Product from the screenshot in the previous section:

   ![Tag management on an object](images/tags-management-on-object.png)

2. Import and Reimport

    Tags can also be applied to a given test at the time of import or reimport. This is a very
    handy use case when importing via the API with automation as it provides an opportunity to
    append automation run details and tool information that may not be captured in the test
    or finding object directly. 

    The field looks and behaves exactly as it does on a given object

3. Bulk Edit Menu (Findings only)

    When needing to update many Findings with the same set of tags, the bulk edit menu can be
    used to ease the burden.

    In the following example, lets say I want to update the tags of the two findings with the tag "tag-group-alpha" to be a new tag list like this ["tag-group-charlie", "tag-group-delta"]. 
    First I would select the tags to be updated:

    ![Select findings for bulk edit tag update](images/tags-select-findings-for-bulk-edit.png)

    Once a finding is selected, a new button appears with the name "Bulk Edit". Clicking this button
    produces a dropdown menu with many options, but the focus is just on tags for now. Update the
    field to have the desired tag list as follows, and click submit

    ![Apply changes for bulk edit tag update](images/tags-bulk-edit-submit.png)

    The tags on the selected Findings will be updated to whatever was specified in the tags field
    within the bulk edit menu

    ![Completed bulk edit tag update](images/tags-bulk-edit-complete.png)

## Tag Inheritance

**Pro UI note: though Tag inheritance can be configured using the Pro UI, inherited Tags currently can only be accessed and filtered for through the Classic UI or the API.**

When Tag Inheritance is enabled, tags applied to a given Product will automatically be applied to all objects under Products in the [Product Hierarchy](/en/working_with_findings/organizing_engagements_tests/Product_hierarchy).

### Configuration

Tag Inheritance can be enabled at the following scope levels:
- Global Scope
  - Every Product system wide will begin applying tags to all children objects (Engagements, Tests and Findings)
  - This is set within the System Settings
- Product Scope
  - Only the selected Product will begin applying tags to all children objects (Engagements, Tests and Findings)
  - This is set at the Product creation/edit page

### Behaviors

When Tag Inheritance is enabled, standard Tags can be added to and removed from objects in the standard way.
However inherited tags cannot be removed from a child object without removing them from the parent object
See the following example of adding a tag "test_only_tag" to the Test object and a tag "engagement_only_tag" to the Engagement.

![Example of inherited tags](images/tags-inherit-exmaple.png)

When updates are made to the tag list on a Product, the same changes are made to all objects within the Product asynchronously. The duration of this task directly correlates to the number the objects contained within a finding.

**Open-Source:** If Tag changes are not observed within a reasonable time period, consult the celery worker logs to identify where any problems might have arisen.


### Filtering for Tags (Classic UI)

Tags can be filtered in many ways through both the UI and the API. For example, here is a snippet
of the Finding filters:

![Snippet of the finding filters](images/tags-finding-filter-snippet.png)

There are ten fields related to tags:

 - Tags: filter on any tags that are attached to a given Finding
   - Examples:
     - Finding will be returned
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "B"
     - Finding Will *not* be returned
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "F"
 - Not Tags: filter on any tags that are *not* attached to a given Finding
   - Examples:
     - Finding will be returned
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "F"
     - Finding Will *not* be returned
       - Finding Tags: ["A", "B", "C"]
       - Filter Query: "B"
 - Tag Name Contains: filter on any tags that contain part or all of the query in the given Finding
   - Examples:
     - Finding will be returned
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "et" (part of "Beta")
     - Finding Will *not* be returned
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "meg" (part of "Omega")
 - Not Tags: filter on any tags that do *not* contain part or all of the query in the given Finding
   - Examples:
     - Finding will be returned
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "meg" (part of "Omega")
     - Finding Will *not* be returned
       - Finding Tags: ["Alpha", "Beta", "Charlie"]
       - Filter Query: "et" (part of "Beta")

For the other six tag filters, they follow the same rules as "Tags" and "Not Tags" as above,
but at different levels in the data model:

 - Tags (Test): filter on any tags that are attached to the Test of a given Finding
 - Not Tags (Test): filter on any tags that are *not* attached to the Test of a given Finding is part  of
 - Tags (Engagement): filter on any tags that are attached to the Engagement of a given Finding
 - Not Tags (Engagement): filter on any tags that are *not* attached to the Engagement of a given Finding is part  of
 - Tags (Product): filter on any tags that are attached to the Product of a given Finding is part of
 - Not Tags (Product): filter on any tags that are *not* attached to the Product of a given Finding
