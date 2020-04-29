{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
<html>
<body>
{% autoescape on %}
<p>
Hello {{ user.get_full_name }},
<br/>
<br/>
{% url 'view_product' test.engagement.product.id as product_url %}
{% url 'view_engagement' test.engagement.id as engagement_url %}
{% url 'view_test' test.id as test_url %}
    A new test has been added: <a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a> / <a href="{{ test_url|full_url }}">{{ test }}</a><br/>
    Finding details in the 'scan_added' email, which is a separate notification (for now).
<br/>
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