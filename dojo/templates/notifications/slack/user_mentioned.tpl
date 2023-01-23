{% load i18n %}{% blocktranslate trimmed %}
User {{ user }} jotted a note on {{ section }}:

{{ note }}

Full details of the note can be reviewed at {{ url }}
{% endblocktranslate %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
