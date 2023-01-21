{% load i18n %}{% blocktranslate trimmed %}
Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url|full_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
