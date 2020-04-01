{% if type == 'mail' %}
    Hello,

    {{ description|safe }}

    {% if url is not None %}
    {{ test }} results have been uploaded.
They can be viewed here: {{ url }}
    {% endif %}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    {{ description|safe }}
{% elif type == 'slack' %}
    {{ description|safe }}

    {% if url is not None %}
         {{ test }} results have been uploaded.
They can be viewed here: {{ url }}
    {% endif %}
{% endif %}
