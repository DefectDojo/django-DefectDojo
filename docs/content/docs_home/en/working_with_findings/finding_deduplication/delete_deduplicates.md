---
title: "Delete Deduplicate Findings"
description: "Remove excess duplicate Findings from DefectDojo"
weight: 3
---

If you have an excessive amount of duplicate Findings which you want to delete, you can set **Delete Deduplicate Findings** as an option in the **System Settings**.

**Delete Deduplicate Findings**, combined with the **Maximum Duplicates** field allows DefectDojo to limit the amount of Duplicate Findings stored. When this field is enabled, DefectDojo will only keep a certain number of Duplicate Findings.

## Which duplicates will be deleted?

The original Finding will never be deleted automatically from DefectDojo, but once the threshold for Maximum Duplicates is crossed, DefectDojo will automatically delete the oldest Duplicate Finding.

For example, let’s say that you had your Maximum Duplicates field set to ‘1’.

1. First, you import **Test 1\.** Your report contains a vulnerability which is recorded as Finding A.
2. **Later, you import Test 2 contains the same vulnerability. This will be recorded as Finding B, and Finding B will be marked as a duplicate of Finding A.**
3. Later still, you import **Test 3** which also contains that vulnerability. This will be recorded as Finding C, which will be marked as a duplicate of Finding A. At this time, Finding B will be deleted from DefectDojo as the threshold for maximum duplicates has been crossed.

## Applying this setting

Applying **Delete Deduplicate Findings** will begin a deletion process immediately. This setting can be applied on the **System Settings** page. See Enabling Deduplication for more information.
