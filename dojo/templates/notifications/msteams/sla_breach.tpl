{% url 'view_finding' finding.id as finding_url %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "title": "SLA breached",
        "summary": "SLA breached",
        "sections": [
            {
                "activityTitle": "DefectDojo",
                "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                "text": "A SLA for a finding has been breached.",
                "facts": [
                    {
                        "name": "Product:",
                        "value": "{{ finding.test.engagement.product.name }}"
                    },
                    {
                        "name": "Engagement:",
                        "value": "{{ finding.test.engagement.name }}"
                    },
                    {
                        "name": "Finding:",
                        "value": "{{ finding.title }}"
                    },
                    {
                        "name": "Severity:",
                        "value": "{{ finding.severity }}"
                    },
                    {
                    "name": "SLA age:",
                    "value": "{{ sla_age }}"
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
