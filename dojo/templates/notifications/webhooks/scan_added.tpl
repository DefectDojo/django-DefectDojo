{% load display_tags %}
{% include 'notifications/webhooks/other.tpl' %}
test: {{ test }}
url: {{ url|full_url }}    
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
disclaimer:  {{ system_settings.disclaimer }}
{% endif %}
