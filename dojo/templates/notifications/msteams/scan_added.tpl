{% url 'view_test' test.id as test_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "Scan added",
    "summary": "Scan added",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "A new scan has been added.",
            "facts": [
                {
                    "name": "Product:",
                    "value": "{{ test.engagement.product.name }}"
                },
                {
                    "name": "Engagement:",
                    "value": "{{ test.engagement.name }}"
                },
                {
                    "name": "Scan:",
                    "value": "{{ test }}"
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
            "name": "View Test",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
