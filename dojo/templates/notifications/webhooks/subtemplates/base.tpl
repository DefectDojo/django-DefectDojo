{% load display_tags %}
---
description: {{ description | default_if_none:'' }}  # TODO add "quote or none" - to all strings
user: {{ user | default_if_none:'' }}
{% if url %}
url:  {{ url|full_url }}
{% endif %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
disclaimer:  {{ system_settings.disclaimer }}
{% endif %}
