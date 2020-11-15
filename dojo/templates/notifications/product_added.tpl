{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
<html>
<body>
{% autoescape on %}
<p>
Hello,
</p>
<p>
The new product "{{ title }}" has been added. It can be viewed here: <a href="{{ url|full_url }}">{{ title }}</a>
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
</html>

{% elif type == 'alert' %}
    The new product "{{ title }}" has been added
{% elif type == 'slack' %}
    The new product "{{ title }}" has been added. It can be viewed here: {{ url|full_url }}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "Product added",
        "summary": "Product added",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "A new product has been added.",
                "facts": [
                    {
                        "name": "Product:",
                        "value": "{{ title }}"
                    }
                ]
            }
        ],
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "View",
            "targets": [
                { "os": "default", "uri": "{{ url|full_url }}" }
                ]
            }
        ]
    }
{% endif %}
