# Dynamic Finding Groups
This module manages dynamic grouping of Findings in DefectDojo. Findings can be grouped using different strategies (called GroupModes) such as:
- Grouping by the vuln_id_from_tool
- Grouping by the Finding title
- Grouping by the associated CVE

The grouping is user-configurable through the UI and relies on Redis for fast storage and retrieval of groups.

## How it works
When a user selects a grouping mode, the system builds and stores finding groups in Redis. These groups are refreshed automatically whenever new Findings are added or existing ones are modified.

### Redis is used to:
- Store the mapping between Findings and their groups.
- Store the serialized representation of each DynamicFindingGroups object.
- Manage timestamps that help us detect if the stored groups are outdated.

### Two global keys are important here:
- finding_groups_last_finding_change: Updated whenever a Finding is created/updated.
- finding_groups_last_update: Stores the last time a specific GroupMode was rebuilt.

### When we rebuild groups:
Group rebuilding occurs in the following cases:
- The groups are missing in Redis, or
- The timestamps `finding_groups_last_finding_change` and `finding_groups_last_update` do not match.

In practice, whenever a change occurs, the value of `last_finding_change` becomes more recent than `last_update`. At that point, the groups are rebuilt, and `last_update` is updated to match `last_finding_change`.

The `last_update` entry stores the timestamp per mode. Whenever a user opens the tab for a given mode, the system compares the timestamps. If they differ, the groups are rebuilt; otherwise, the existing groups are reused.

## Adding a new GroupMode
To add a new grouping strategy:

1. Extend the GroupMode enum. Add a new entry, for example:
```python
class GroupMode(StrEnum):
    VULN_ID_FROM_TOOL = "vuln_id_from_tool"
    TITLE = "title"
    CVE = "cve"
    CUSTOM_TAG = "custom_tag"   # ← New mode
```

2. Update `DynamicFindingGroups.get_group_names`. Define how the Finding should be grouped for the new mode:
```python
if mode == GroupMode.CUSTOM_TAG:
    return finding.custom_tags.all().values_list("name", flat=True)
```

3. Expose the mode in the HTML select box. Edit `finding_groups_dynamic_list_snippet.html` to allow the user to select it:
```html
<option value="custom_tag" {% if mode == "custom_tag" %}selected{% endif %}>Custom Tag</option>
```

## User selection in the UI
Users must explicitly choose a grouping mode in the UI for this feature to take effect.
The selection is available in `finding_groups_dynamic_list_snippet.html`:
```html
<form method="get" class="form-inline mb-3">
    <label for="mode-select" class="mr-2">{% trans "Group Mode:" %}</label>
    <select name="mode" id="mode-select" onchange="this.form.submit()">
        <option value="" {% if not mode %}selected{% endif %}></option>
        <option value="vuln_id_from_tool" {% if mode == "vuln_id_from_tool" %}selected{% endif %}>Vuln ID from Tool</option>
        <option value="title" {% if mode == "title" %}selected{% endif %}>Title</option>
        <option value="cve" {% if mode == "cve" %}selected{% endif %}>CVE</option>
    </select>
</form>
```
If no mode is selected, **Redis will not be used** and no dynamic finding groups will be built.

## Summary
- Redis stores groups and manages synchronization via timestamps.
- Groups are rebuilt only when necessary.
- Adding a new GroupMode requires extending the enum, defining the grouping logic, and updating the HTML select box.
- Users must explicitly select a mode in the UI; otherwise, grouping is disabled.