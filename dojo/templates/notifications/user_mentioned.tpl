{% load get_system_setting %}

{% if type == 'mail' %}
    Hello,

    User {{ user }} jotted a note on {{ section }}:

    {{ note }}

    It can be reviewed at {{ url }}

    Kind regards,
    {{ "team_name"|get_system_setting }}
{% elif type == 'alert' %}
    User {{ user }} jotted a note on {{ section }}:

    {{ note }}
{% elif type == 'slack' %}
    User {{ user }} jotted a note on {{ section }}:

{{ note }}

Full details of the note can be reviewed at {{ url }}
{% endif %}