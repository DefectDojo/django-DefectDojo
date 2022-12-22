{% url 'view_test' test.id as test_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    {% if risk_acceptance.is_expired %}
        "title": "Risk Acceptance Expired",
        "summary": "Risk Acceptance Expired",
    {% else %}
        "title": "Risk Acceptance Will Expire Soon",
        "summary": "Risk Acceptance Will Expire Soon",
    {% endif %}
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            {% if risk_acceptance.is_expired %}
                "text": "Risk acceptance {{ risk_acceptance }} with {{ risk_acceptance.accepted_findings.all| length }} has expired {{ risk_acceptance.expiration_date_handled|date }}",
            {% else %}
                "text": "Risk acceptance {{ risk_acceptance }} with {{ risk_acceptance.accepted_findings.all| length }} will expire {{ risk_acceptance.expiration_date|date }}",
            {% endif %}
            "facts": [
                {
                    "name": "Product:",
                    "value": "{{ risk_acceptance.engagement.product.name }}"
                },
                {
                    "name": "Engagement:",
                    "value": "{{ risk_acceptance.engagement.name }}"
                },
                {
                    "name": "Risk Acceptance:",
                    "value": "{{ risk_acceptance }}"
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
            "name": "View Risk Acceptance",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
