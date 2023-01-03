{% load i18n %}{% blocktranslate trimmed %}
SLA breach alert for finding {{ finding.id }}. Relative days count to SLA due date: {{sla_age}}.
Title: {{finding.title}}
Severity: {{finding.severity}}
You can find details here: {{ url|full_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
