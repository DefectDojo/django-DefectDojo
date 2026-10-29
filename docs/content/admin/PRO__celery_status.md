---
title: "Celery Status"
description: "Check the health of DefectDojo's background-task queue, see which tasks are waiting, and purge stuck work"
weight: 10
audience: pro
draft: false
---

Celery Status is a page that shows whether DefectDojo's background-task system is working. DefectDojo runs a lot of its work in the background with Celery: scan imports and reimports, deduplication, notifications, and other jobs that should not hold up a web request. Those jobs wait in a queue on the Redis broker until a Celery worker picks them up. When imports look stuck, duplicates are not being closed, or notifications stop arriving, this page tells you whether the broker is up, whether a worker is running, how many tasks are waiting, and which tasks they are.

Celery Status is a **DefectDojo Pro** feature. It is on for every instance, Cloud and On-Premise, and there is nothing to enable.

## Who can see it

Only **superusers** can use Celery Status. The menu entry is hidden from everyone else, and the API behind the page refuses requests from users who are not superusers. Global Owners and other global roles do not get access.

## Where to find it

Go to **Settings > Operations > Celery Status**. On older versions of the menu it was **Settings > Pro Settings > Celery Status** (see [the sidebar mapping](/navigation/pro__sidebar/)).

The page has three cards: **Status and Queue**, **Queue Details**, and **Celery Task Limits (Read-Only)**.

## Status and Queue

This card loads when you open the page. Use the **Refresh** button in the card header to load it again.

| Field | What it shows |
| --- | --- |
| **Redis Broker** | **Reachable** (green) if DefectDojo could read the queue on the broker. **Unreachable** (red) if it could not. |
| **Celery Worker** | **Running** (green) if at least one Celery worker answered a ping within 3 seconds. **Not Running** (red) if none did. The ping uses Celery's control channel instead of the task queue, so it still answers when the queue is backed up. |
| **Queue** | The number of tasks waiting to be processed, for example "42 tasks waiting to be processed." If the broker cannot be read, it says "It is not possible to identify the number of waiting tasks." |
| **Queue Actions** | The **Purge Queue** and **View Details** buttons. Both are disabled, with the hint "Broker unreachable", when the queue length cannot be read. |

A waiting count that stays high or keeps growing while **Celery Worker** shows **Running** means the workers cannot keep up, or one kind of task is flooding the queue. A count that grows while the worker shows **Not Running** means nothing is processing the queue at all. Check that your worker containers or pods are up.

## Queue Details

The per-task breakdown is not loaded automatically, because building it reads every message in the queue and can be slow on a large queue. Click **View Details** under **Queue Actions** to load it, and **Hide Details** to close it. While the details are open, the refresh button in the **Queue Details** header (**Refresh queue details**) reloads them.

Each row is one task name, in queue order by its oldest message. If the queue has nothing in it, the table shows "Queue is empty."

| Column | What it means |
| --- | --- |
| Gear menu | Holds the **Purge** action for that task name (see [Purging tasks](#purging-tasks)). |
| **#** | The row number. |
| **Task Name** | The Celery task name, for example `dojo.tasks.example_task`. |
| **Count** | How many messages with this task name are waiting. |
| **Oldest (Queue Pos.)** | The queue position of the oldest waiting message for this task. Position 1 is the oldest message in the whole queue. If the message has a scheduled run time (ETA), it is shown in parentheses. |
| **Newest (Queue Pos.)** | The queue position of the newest waiting message for this task, with its ETA in parentheses when set. |
| **Expires** | When the waiting messages for this task expire. **Oldest:** is the earliest expiry and **Newest:** is the latest. Each shows the time left (for example "2h 15m Left"), or a red **Expired** tag if that time has passed. |

An **Expired** tag matters. A task that sits in the queue past its expiry time is discarded by Celery when a worker reaches it. It never runs and no error is raised. If you see expired tasks for imports or deduplication, that work will not happen unless it is started again.

## Celery Task Limits (Read-Only)

This card shows the task timeouts DefectDojo is running with. You cannot change them on this page. They are set with environment variables on the DefectDojo containers.

| Field | Environment variable | What it controls |
| --- | --- | --- |
| **Task Time Limit (Hard Kill)** | `DD_CELERY_TASK_TIME_LIMIT` | The longest a task may run. When it is reached the worker process is killed and no cleanup code runs. Default 12 hours. |
| **Task Soft Time Limit** | `DD_CELERY_TASK_SOFT_TIME_LIMIT` | Raises an exception inside the task so it can clean up before the hard limit. Off by default. |
| **Default Task Expiry (Queue)** | `DD_CELERY_TASK_DEFAULT_EXPIRES` | How long a task may wait in the queue before Celery discards it unrun. Default 12 hours. |

Each value is shown as a duration with the raw number of seconds in parentheses, for example "12h (43200s)". **Not set** means the limit is turned off (the variable is `0`).

## Purging tasks

Purging deletes waiting tasks from the queue. **The work those tasks would have done is discarded and is not retried.** A purged import never finishes processing, a purged deduplication task never runs, and a purged notification is never sent. A purge cannot be undone. Tasks that a worker is already running are not affected.

Only superusers see the purge actions, and each one asks you to confirm first.

### Purge Queue

**Purge Queue** under **Queue Actions** removes every waiting task from the queue, whatever its name. The confirmation reads "Purge all pending tasks from the queue? This cannot be undone." On success, a message reports how many tasks were purged, and the page reloads the status and, if open, the queue details.

### Purge one task name

In **Queue Details**, open the gear menu on a row and choose **Purge**. This removes only the waiting messages with that task name and leaves everything else in the queue. Use it when one kind of task is flooding the queue and holding up the rest.

A single per-task purge removes at most 10,000 tasks and works through them in batches of 1,000. If more than 10,000 are waiting, run the purge again. Both numbers can be changed with `DD_CELERY_QUEUE_PURGE_MAX_TASKS` and `DD_CELERY_QUEUE_PURGE_BATCH_SIZE`.

### After a purge: re-run deduplication

If deduplication tasks were in the queue when you purged, those findings were not deduplicated. On a self-hosted instance, re-run deduplication with the `dedupe` management command:

```
python manage.py dedupe --dedupe_only
```

On DefectDojo Cloud, contact [DefectDojo Support](mailto:support@defectdojo.com) to have it run.

Purged imports also need to be run again. Re-upload the scan file, or wait for the next scheduled import or connector sync.

## When to use it

* **Imports stay in progress.** Check whether **Celery Worker** shows **Running** and whether the queue is growing. If the workers are down, restart them. Do not purge.
* **Duplicates are not being marked.** Open **Queue Details** and look for a large count of deduplication tasks, or an **Expired** tag on them.
* **Notifications are late or missing.** Look for a backlog of notification tasks behind other work.
* **One task type is flooding the queue.** Purge that task name only, then start the discarded work again. Use **Purge Queue** only when you accept losing everything that is waiting.

Purging clears a backlog but does not fix what caused it. If the queue fills up again, check worker capacity and logs before purging a second time.
