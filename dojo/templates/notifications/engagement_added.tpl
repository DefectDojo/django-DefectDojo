{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' test.engagement.product.id as product_url %}
{% url 'view_engagement' test.engagement.id as engagement_url %}
<html>
<body>
{% autoescape on %}
<p>
Hello,
</p>
<p>
The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}". It can be viewed here: <a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a>
</p>
<br/>
<br/>
Kind regards,<br/>
<br/>
{% if system_settings.team_name is not None %}
{{ system_settings.team_name }}
{% else %}
Defect Dojo
{% endif %}
<p>
<br/>
<br/>
<p>
{% url 'notifications' as notification_url %}
You can manage your notification settings here: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
</p>
{% endautoescape %}
</body>
<html>

{% elif type == 'alert' %}
    The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}".
{% elif type == 'slack' %}
    The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}". It can be viewed here: {{ url|full_url }}
{% endif %}