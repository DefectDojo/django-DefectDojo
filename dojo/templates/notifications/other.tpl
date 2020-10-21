{% if type == 'mail' %}
    Hello,

    {{ description|safe }}{% if url is not None %}
    More information on this event can be found here: {{ url }}
    {% endif %}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    {{ description|safe }}
{% elif type == 'slack' %}
    {{ description|safe }}{% if url is not None %}
More information on this event can be found here: {{ url }}
    {% endif %}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "Event",
        "summary": "Event",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "{% autoescape on %} {{ description }} {% endautoescape %}"
            }
        ],
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "View",
            "targets": [
                { "os": "default", "uri": "{{ url }}" }
                ]
            }
        ]
    }
{% endif %}