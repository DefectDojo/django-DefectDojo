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
        "title": "User mentioned",
        "summary": "User mentioned",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "A user has been mentioned.",
                "facts": [
                    {
                        "name": "User:",
                        "value": "{{ user }}"
                    },
                    {
                        "name": "Section:",
                        "value": "{{ section }}"
                    },
                    {
                        "name": "note:",
                        "value": "{{ note }}"
                    }
                ]
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