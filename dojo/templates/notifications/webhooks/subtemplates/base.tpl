{% load display_tags %}
---
description: "{{ description | default_if_none:'' | tojson(0) }}"
title: "{{ title | default_if_none:'' | tojson(0) }}"
user: {{ user | default_if_none:'' | tojson(0) }}
{% if url %}
url_ui:  {{ url | full_url | tojson(0) }}
{% endif %}
{% if url_api %}
url_api:  {{ url_api | full_url | tojson(0) }}
{% endif %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
disclaimer:  {{ system_settings.disclaimer_notifications | tojson(0) }}
{% endif %}
