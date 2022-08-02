---
title: "Performance Enhancements"
description: "Settings to configure to enhance performance in DefectDojo"
draft: false
weight: 4
---

## Asynchronous Import

DefectDojo offers an experimental feature to aynschronously import security reports. 
This feature works in most use cases, but struggles when doing things such as pushing 
to Jira during the import process. Because Endpoints are still being processed and 
created even after the import procedure is completed, pushing Findings to Jira can
result in incomplete Jira tickets. It is advised to wait until after import has been
completed 100%.

To enable this feature, set `ASYNC_FINDING_IMPORT` to True in `local_settings.py`

## Asynchronous Delete

For larger instances, deleting an object can take minutes for all related objects to be 
expanded into memory, rendered on the page, and then removing all objects from the database.
To combat this issue, two settings can be set in `local_settings.py`:

#### ASYNC_OBJECT_DELETE

Deleting an object asynchronously changes the way an object is deleted under the hood. By removing
the need to expand into memory, a lot of time (and memory) can be saved by offloading the lookups and
removals onto celery processes. This process works by starting at the bottom of a given object, and 
walking the tree upwards rather than downwards. This way, objects can be seperated into buckets,
and then deleted.

#### DELETE_PREVIEW

Previewing all the objects to be deleted takes almost as much time as deleting the objects itself.
This is a safety feature intended to warn users of what they are about to delete, as well as educating 
users of how the delete functionality works by cascade deleting all related objects. With this feature enabled, 
the user will only see the following text in the delete preview (without any database lookups)

`Previewing the relationships has been disabled.`
