# Fix: JIRA push eligibility check blocks unrelated PATCH requests

## Bug

PATCH requests on findings (e.g. EPSS enrichment) fail with HTTP 400:

```
"Finding: X cannot be pushed to JIRA: Findings must be active and verified,
 if enforced by system settings, to be pushed to JIRA."
```

The EPSS update is rolled back due to `ATOMIC_REQUESTS`.

## Root cause

Two PRs introduced between 2.52.3 and 2.55.4 combined to cause this:

### PR #14262 — "Jira keep findings in sync" (2.55.2)

`FindingSerializer.update()` in `dojo/api_v2/serializers.py` was changed to
trigger a JIRA push even when `push_to_jira` was not explicitly set:

```python
# before
if push_to_jira:
    jira_helper.push_to_jira(instance)

# after
if push_to_jira or finding_helper.is_keep_in_sync_with_jira(instance):
    jira_helper.push_to_jira(instance, sync=True)
```

This means any PATCH — including EPSS enrichment — triggers a JIRA push when:
- `jira_project.push_all_issues` is True (resolved in `perform_update` before
  calling `serializer.save`), OR
- `finding_jira_sync` is enabled on the JIRA instance and the finding (or its
  group) already has a JIRA issue

### PR #14320 — "Fix Jira error handling" (2.55.3)

`push_to_jira` return value (previously ignored) is now checked, and any
failure raises a `ValidationError`:

```python
# after
success, message = jira_helper.push_to_jira(instance, sync=True)
if not success:
    raise serializers.ValidationError(message)
```

`add_jira_issue` in `helper.py` already classifies "not active/verified" and
"below threshold" as *expected* eligibility failures and logs them at INFO
level — but it still returns `(False, message)`, which the serializer now
unconditionally raises as a 400.

## Existing pattern

`dojo/finding/views.py` (bulk edit, lines ~2963-3024) already does this
correctly: it calls `can_be_pushed_to_jira` as a guard before attempting the
push. If ineligible, it logs and skips — no exception is raised.

## Fix

### 1. `dojo/api_v2/views.py` — `FindingViewSet.perform_update()`

Capture whether the push was *explicitly* requested before merging with
`push_all_issues`:

```python
push_to_jira = serializer.validated_data.get("push_to_jira")
push_to_jira_explicit = bool(push_to_jira)          # explicit before OR
jira_project = jira_helper.get_jira_project(serializer.instance)
if get_system_setting("enable_jira") and jira_project:
    push_to_jira = push_to_jira or jira_project.push_all_issues
serializer.save(push_to_jira=push_to_jira, push_to_jira_explicit=push_to_jira_explicit)
```

### 2. `dojo/api_v2/serializers.py` — `FindingSerializer.update()`

Guard with `can_be_pushed_to_jira` (same pattern as bulk edit view).
Only raise `ValidationError` for eligibility failures when the push was
explicitly requested by the caller; auto-triggered pushes skip silently:

```python
push_to_jira = validated_data.pop("push_to_jira")
push_to_jira_explicit = validated_data.pop("push_to_jira_explicit", False)

...

if push_to_jira or finding_helper.is_keep_in_sync_with_jira(instance):
    can_push, error_message, _error_code = jira_helper.can_be_pushed_to_jira(instance)
    if can_push:
        # Push synchronously so that we can see jira errors in real time
        success, message = jira_helper.push_to_jira(instance, sync=True)
        if not success:
            raise serializers.ValidationError(message)
    elif push_to_jira_explicit:
        # User explicitly asked to push — surface the eligibility error
        raise serializers.ValidationError(error_message)
    # else: auto-triggered (push_all_issues / finding_jira_sync) but finding
    # is not eligible → silently skip, same as bulk edit view
```

## Behaviour after fix

| Trigger | Finding eligible | Result |
|---|---|---|
| Explicit `push_to_jira=true` | yes | push, raise on push failure |
| Explicit `push_to_jira=true` | no | raise 400 (expected, user asked) |
| Auto (`push_all_issues` / sync) | yes | push, raise on push failure |
| Auto (`push_all_issues` / sync) | no | silently skip, PATCH succeeds |
