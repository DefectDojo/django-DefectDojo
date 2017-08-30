{% load get_system_setting %}

{% if type == 'mail' %}
    Hello,

    the engagement "{{ engagement.product }}" has been created. It can be viewed here: {{ url }}

    Kind regards,
    {{ "team_name"|get_system_setting }}
{% elif type == 'alert' %}
    The engagement "{{ engagement.product }}" has been created.
{% elif type == 'slack' %}
    The engagement "{{ engagement.product }}" has been created. It can be viewed here: {{ url }}
{% endif %}