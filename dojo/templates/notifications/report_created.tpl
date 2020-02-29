{% if type == 'mail' %}
    Greetings,

    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    Your report "{{ report.name }}" is ready.
{% elif type == 'slack' %}
    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}
{% endif %}