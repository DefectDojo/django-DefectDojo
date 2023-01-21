{% load i18n %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "User Mentioned" %}",
    "summary": "{% trans "User Mentioned" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "A user has been mentioned" %}.",
            "facts": [
                {
                    "name": "{% trans "User" %}:",
                    "value": "{{ user }}"
                },
                {
                    "name": "{% trans "Section" %}:",
                    "value": "{{ section }}"
                },
                {
                    "name": "{% trans "note" %}:",
                    "value": "{{ note }}"
                }
            ]
        }
        {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
            ,{
                "activityTitle": "{% trans "Disclaimer" %}",
                "text": "{{ system_settings.disclaimer }}"
            }
        {% endif %}
    ],
    "potentialAction": [
        {
            "@type": "OpenUri",
            "name": "{% trans "View" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
