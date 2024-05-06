{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with name=report.name report_url=url|full_url %}
Your report "{{ name }}" is ready. It can be downloaded here: {{ report_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
