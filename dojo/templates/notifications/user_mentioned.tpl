{% load get_system_setting %}

{% if type == 'mail' %}
    Hello,

    User {{ user }} mentioned you in a note on {{ section }}:

    {{ note }}

    It can be reviewed at {{ url }}

    Kind regards,
    {{ "team_name"|get_system_setting }}
{% elif type == 'alert' %}
    User {{ user }} mentioned you in a note on {{ section }}:

    {{ note }}
{% elif type == 'slack' %}
    User {{ user.usercontactinfo.slack_username }} mentioned you in a note on {{ section }}:

    {{ note }}

    It can be reviewed at {{ url }}
{% endif %}