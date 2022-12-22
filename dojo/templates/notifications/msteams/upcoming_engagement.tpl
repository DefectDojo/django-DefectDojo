{% url 'view_engagement' engagement.id as engagement_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "Engagement is starting",
    "summary": "Engagement is starting",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "An Engagement is starting.",
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
                    "name": "Start date:",
                    "value": "{{ engagement.target_start }}"
                },
                {
                    "name": "End date:",
                    "value": "{{ engagement.target_end }}"
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
            "name": "View Engagement",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
