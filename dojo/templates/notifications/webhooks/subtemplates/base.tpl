{% load display_tags %}
{% load as_json %}
---
description: {{ description | as_json_no_html_esc }}
title: {{ title | as_json_no_html_esc }}
user: {{ user | as_json_no_html_esc }}
{% if url %}
url_ui:  {{ url | full_url | as_json_no_html_esc }}
{% endif %}
{% if url_api %}
url_api:  {{ url_api | full_url | as_json_no_html_esc }}
{% endif %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
disclaimer:  {{ system_settings.disclaimer_notifications | as_json_no_html_esc }}
{% endif %}
