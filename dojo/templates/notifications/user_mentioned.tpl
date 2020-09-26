{% if type == 'mail' %}
    Hello,

    User {{ user }} jotted a note on {{ section }}:

    {{ note }}

    It can be reviewed at {{ url }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    User {{ user }} jotted a note on {{ section }}:

    {{ note }}
{% elif type == 'slack' %}
    User {{ user }} jotted a note on {{ section }}:

{{ note }}

Full details of the note can be reviewed at {{ url }}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": "0072C6",
        "title": "Engagement added",
        "text": "User {{ user }} jotted a note on {{ section }}: {{ note }}",
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