{% load i18n %}
{{ description|safe }}
{% if url is not None %}
{% blocktranslate trimmed %}
    More information on this event can be found here: {{ url|full_url }}
{% endblocktranslate %}
{% endif %}
{% if system_settings.disclaimer|length %}

    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
