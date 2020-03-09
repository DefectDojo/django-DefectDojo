{% if type == 'mail' %}
    Greetings,

    A new test has been added to the engagement {{ engagement.product }}.
    Title: {{test.title}}
    Type: {{ test.test_type }}
    You can find details here: {{ url }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    New test added for engagement {{ engagement.product }}: {{ test.test_type }}.
{% elif type == 'slack' %}
    New test added for engagement {{ engagement.product }}.
Title: {{test.title}}
Type: {{ test.test_type }}
You can find details here: {{ url }}
{% endif %}