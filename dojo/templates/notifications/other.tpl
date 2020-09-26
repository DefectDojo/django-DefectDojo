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
        "themeColor": "0072C6",
        "title": "Other event",
        "text": "{{ description|safe }}",
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