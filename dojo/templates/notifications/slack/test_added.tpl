{% load i18n %}{% blocktranslate trimmed %}
New test added for engagement {{engagement.name }} in product {{ engagement.product}}.
Title: {{test.title}}
Type: {{ test.test_type }}
You can find details here: {{ url|full_url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
