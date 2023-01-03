{% load i18n %}{% blocktranslate trimmed %}
The new product "{{ title }}" has been added. It can be viewed here: {{ url|full_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
