{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with id=finding.id title=finding.title severity=finding.severity sla_url=url|full_url %}
SLA breach alert for finding {{ id }}. Relative days count to SLA due date: {{sla_age}}.
Title: {{title}}
Severity: {{severity}}
You can find details here: {{ sla_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
