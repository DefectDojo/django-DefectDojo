{% if type == 'mail' %}
<html>
<body>
{% autoescape on %}
<p>
Hello {{ user.get_full_name }},
<br/>
</br>
    A new test has been added to the engagement {{ engagement.product }}</br>
    Title: {{test.title}}</br>
    Type: {{ test.test_type }}</br>
    You can find details here: <a href="{{ absolute_url }}">findings</a></br>
    More details in the next email with updated finding results.
</br>
    Kind regards,</br>
{% if system_settings.team_name is not None %}
{{ system_settings.team_name }}</br>
{% else %}
Defect Dojo</br>
{% endif %}
<p>
{% endautoescape %}
</body>
<html>
{% elif type == 'alert' %}
    New test added for engagement {{ engagement.product }}: {{ test.test_type }}.
{% elif type == 'slack' %}
    New test added for engagement {{ engagement.product }}.
Title: {{test.title}}
Type: {{ test.test_type }}
You can find details here: {{ url }}
{% endif %}