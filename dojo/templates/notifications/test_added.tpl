{% load get_system_setting %}

{% if type == 'mail' %}
    Greetings,

    a new test has been added to the engagement {{ engagement.product }}: {{ test.test_type }}. You can find details here: {{ url }}

    Kind regards,
    {{ "team_name"|get_system_setting }}
{% elif type == 'alert' %}
    New test added for engagement {{ engagement.product }}: {{ test.test_type }}.
{% elif type == 'slack' %}
    New test added for engagement {{ engagement.product }}: {{ test.test_type }}. You can find details here: {{ url }}
{% endif %}