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
            "name": "Download",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
