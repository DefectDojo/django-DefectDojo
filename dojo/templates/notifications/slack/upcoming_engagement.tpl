{% load i18n %}{% blocktranslate trimmed with eng_product=engagement.product start=engagement.target_start %}
The engagement "{{ eng_product }}" is starting on {{ start }}.
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
