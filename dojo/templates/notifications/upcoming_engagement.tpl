{% if type == 'mail' %}
    Hello,

    this is a reminder that the engagement "{{ engagement.product }}" is about to start shortly.
    
    Project start: {{ engagement.target_start }}
    Project end: {{ engagement.target_end }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}.
{% elif type == 'slack' %}
    The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}.
{% elif type == 'msteams' %}
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
        ],
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "View",
            "targets": [
                { "os": "default", "uri": "{{ engagement_url|full_url }}" }
                ]
            }
        ]
    }
{% endif %}