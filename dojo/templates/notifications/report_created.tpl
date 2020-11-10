{% if type == 'mail' %}
    Greetings,

    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    Your report "{{ report.name }}" is ready.
{% elif type == 'slack' %}
    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "Report created",
        "summary": "Report created",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "Report is ready for download.",
                "facts": [
                    {
                        "name": "Report:",
                        "value": "report.name"
                    }
                ]
            }
        ],
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "Download",
            "targets": [
                { "os": "default", "uri": "{{ url }}" }
                ]
            }
        ]
    }
{% endif %}