{% url 'view_test' test.id as test_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "Test added",
    "summary": "Test added",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "A new test has been added.",
            "facts": [
                {
                    "name": "Product:",
                    "value": "{{ engagement.product.name }}"
                },
                {
                    "name": "Engagement:",
                    "value": "{{ engagement.name }}"
                },
                {
                    "name": "Test:",
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
