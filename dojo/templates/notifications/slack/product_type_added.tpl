{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with prod_url=url|full_url %}
The new product type "{{ title }}" has been added. It can be viewed here: {{ prod_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
