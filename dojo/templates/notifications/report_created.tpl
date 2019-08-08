{% load get_system_setting %}

{% if type == 'mail' %}
    Greetings,

    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}

    Kind regards,
    {{ "team_name"|get_system_setting }}
{% elif type == 'alert' %}
    Your report "{{ report.name }}" is ready.
{% elif type == 'slack' %}
    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}
{% endif %}