{% if type == 'mail' %}
    Hello,

    {{ description|safe }}{% if url is not None %}
    More information on this event can be found here: {{ url }}
    {% endif %}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    {{ description|safe }}
{% elif type == 'slack' %}
    {{ description|safe }}{% if url is not None %}
More information on this event can be found here: {{ url }}
    {% endif %}
{% endif %}