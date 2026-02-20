---
name: Celery Queue Status UI
overview: Add two API endpoints for celery status/purge, expose new DD_ task limit env vars in settings, and update the system settings page to consume those endpoints via AJAX instead of server-side rendering.
todos:
  - id: fix-worker-status
    content: Replace get_celery_worker_status() in utils.py with app.control.ping(); add purge_celery_queue()
    status: completed
  - id: add-settings
    content: Add DD_CELERY_TASK_TIME_LIMIT, DD_CELERY_TASK_SOFT_TIME_LIMIT, DD_CELERY_TASK_DEFAULT_EXPIRES to settings.dist.py
    status: completed
  - id: add-serializer
    content: Add CeleryStatusSerializer to api_v2/serializers.py
    status: completed
  - id: add-api-views
    content: Add CeleryStatusView and CeleryQueuePurgeView to api_v2/views.py
    status: completed
  - id: register-urls
    content: Register the two new API views in urls.py
    status: completed
  - id: update-django-view
    content: Remove server-side celery status rendering from system_settings/views.py
    status: completed
  - id: update-template
    content: Replace server-rendered celery panel with AJAX-populated panel and JS purge button in system_settings.html
    status: completed
isProject: false
---

# Celery Queue Status UI Improvements

All celery status data moves from server-side Django view rendering to two new REST API endpoints. The system settings page fetches data via AJAX on load and uses a JS-driven purge button. This makes the same endpoints reusable by dojo-pro.

## Architecture

```mermaid
flowchart TD
    Browser -->|"GET /api/v2/celery/status/"| CeleryStatusView
    Browser -->|"POST /api/v2/celery/queue/purge/"| CeleryQueuePurgeView

    CeleryStatusView --> ping["app.control.ping()\n(pidbox control channel)"]
    CeleryStatusView --> qsize["kombu SimpleQueue.qsize()\n(direct broker query)"]
    CeleryStatusView --> cfgRead["getattr(settings, CELERY_TASK_*)"]

    CeleryQueuePurgeView --> purge["channel.queue_purge('celery')\n(direct broker op)"]

    Browser -->|"GET /system_settings"| DjangoView["SystemSettingsView\n(renders template only,\nno celery data)"]
    DjangoView --> Template
    Template -->|"$.get on page load"| CeleryStatusView
    Template -->|"$.ajax POST on click"| CeleryQueuePurgeView
```

## Files changed

1. `dojo/utils.py` — fixed `get_celery_worker_status()` to use `app.control.ping()`; added `purge_celery_queue()`
2. `dojo/settings/settings.dist.py` — added `DD_CELERY_TASK_TIME_LIMIT`, `DD_CELERY_TASK_SOFT_TIME_LIMIT`, `DD_CELERY_TASK_DEFAULT_EXPIRES`
3. `dojo/api_v2/serializers.py` — added `CeleryStatusSerializer`
4. `dojo/api_v2/views.py` — added `CeleryStatusView` and `CeleryQueuePurgeView`
5. `dojo/urls.py` — registered the two new API views
6. `dojo/system_settings/views.py` — removed server-side celery status rendering
7. `dojo/templates/dojo/system_settings.html` — replaced server-rendered celery panel with AJAX-driven panel
