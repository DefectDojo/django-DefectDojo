{% load i18n %}{% blocktranslate trimmed %}
The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}.
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
