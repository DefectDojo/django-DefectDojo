{% load i18n %}
{% url 'view_test' test.id as test_url %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    {% if risk_acceptance.is_expired %}
        "title": "{% trans "Risk Acceptance Expired" %}",
        "summary": "{% trans "Risk Acceptance Expired" %}",
    {% else %}
        "title": "{% trans "Risk Acceptance Will Expire Soon" %}",
        "summary": "{% trans "Risk Acceptance Will Expire Soon" %}",
    {% endif %}
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            {% if risk_acceptance.is_expired %}
                "text": "{% blocktranslate %}Risk acceptance {{ risk_acceptance }} with {{ risk_acceptance.accepted_findings.all| length }} has expired {{ risk_acceptance.expiration_date_handled|date }}{% endblocktranslate %}",
            {% else %}
                "text": "{% blocktranslate %}Risk acceptance {{ risk_acceptance }} with {{ risk_acceptance.accepted_findings.all| length }} will expire {{ risk_acceptance.expiration_date|date }}{% endblocktranslate %}",
            {% endif %}
            "facts": [
                {
                    "name": "{% trans "Product" %}:",
                    "value": "{{ risk_acceptance.engagement.product.name }}"
                },
                {
                    "name": "{% trans "Engagement" %}:",
                    "value": "{{ risk_acceptance.engagement.name }}"
                },
                {
                    "name": "{% trans "Risk Acceptance" %}:",
                    "value": "{{ risk_acceptance }}"
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
            "name": "{% trans "View Risk Acceptance" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
