{{ description|safe }}
{% if url is not None %}
    More information on this event can be found here: {{ url|full_url }}
{% endif %}
{% if system_settings.disclaimer|length %}

    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
