{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "User Mentioned",
    "summary": "User Mentioned",
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
        {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
            ,{
                "activityTitle": "Disclaimer",
                "text": "{{ system_settings.disclaimer }}"
            }
        {% endif %}
    ],
    "potentialAction": [
        {
            "@type": "OpenUri",
            "name": "View",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
