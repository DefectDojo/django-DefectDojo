{% load get_system_setting %}

{% if type == 'mail' %}
    Hello,

    {{ description|safe }}

    {% if url is not None %}
    More information on this event can be found here: {{ url }}
    {% endif %}

    Kind regards,
    {{ "team_name"|get_system_setting }}
{% elif type == 'alert' %}
    {{ description|safe }}
{% elif type == 'slack' %}
    {{ description|safe }}

    {% if url is not None %}
        More information on this event can be found here: {{ url }}
    {% endif %}
{% endif %}
