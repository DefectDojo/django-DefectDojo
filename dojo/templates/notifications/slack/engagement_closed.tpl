{% load i18n %}
{% load display_tags %}
{% blocktranslate trimmed with name=engagement.name eng_product=engagement.product eng_url=url|full_url %}
The engagement "{{ name }}" has been closed in the product "{{ eng_product }}". It can be viewed here: {{ eng_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
