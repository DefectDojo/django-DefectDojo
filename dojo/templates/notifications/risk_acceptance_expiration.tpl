{% if type == 'mail' %}
    {% load navigation_tags %}
    {% load display_tags %}
    {% url 'view_risk_acceptance' risk_acceptance.engagement.id risk_acceptance.id as risk_acceptance_url %}
    {% url 'view_product' risk_acceptance.engagement.product.id as product_url %}
    {% url 'view_engagement' risk_acceptance.engagement.id as engagement_url %}
    <html>
        <body>
            {% autoescape on %}
                <p>
                    Hello {{ user.get_full_name }},
                </p>
                <p>
                    {{ description }}
                    <br/><br/>
                
                    {% if risk_acceptance.is_expired %}
                        <a href="{{risk_acceptance_url|full_url}}">Risk acceptance {{ risk_acceptance }}</a> with {{ risk_acceptance.accepted_findings.all| length }} has expired {{ risk_acceptance.expiration_date_handled|date }}
                    {% else %}
                        <a href="{{risk_acceptance_url|full_url}}">Risk acceptance {{ risk_acceptance }}</a> with {{ risk_acceptance.accepted_findings.all| length }} will expire {{ risk_acceptance.expiration_date|date }}
                    {% endif %}
                    <br/>
                    {% if risk_acceptance.reactivate_expired %}
                        <p>Findings have been reactivated</p>
                    {% endif %}
                    <br/>
                    {% if risk_acceptance.restart_sla_expired %}
                        <p>Findings SLA start date have been reset</p>
                    {% endif %}
                    <br/>
                    <p>
                        Findings:
                        <br/>
                        {% for finding in risk_acceptance.accepted_findings.all %}
                            {% url 'view_finding' finding.id as finding_url %}
                            <a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }}) {{ finding.status }}<br/>
                        {% empty %}
                            None<br/>
                        {% endfor %}
                    </p>
                    <br/><br/>
                    Kind regards,
                    <br/><br/>
                    {% if system_settings.team_name %}
                            {{ system_settings.team_name }}
                        {% else %}
                            Defect Dojo
                        {% endif %}
                    <br/>
                    <br/>
                    <p>
                        {% url 'notifications' as notification_url %}
                        You can manage your notification settings here: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
                    </p>
                    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
                        <br/>
                        <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
                            <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">Disclaimer</span><br/>
                            <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer }}</p>
                        </div>
                    {% endif %}
            {% endautoescape %}
        </body>
    </html>
{% elif type == 'alert' %}
    {{ description }}
{% elif type == 'slack' %}
    {{ description }}

    {% if risk_acceptance.is_expired %}
        Risk Acceptance Expired
    {% else %}
        Risk Acceptance Will Expire Soon
    {% endif %}

    Risk Acceptance can be viewed here: {{ risk_acceptance_url|full_url }}
    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
        
        Disclaimer:
        {{ system_settings.disclaimer }}
    {% endif %}
{% elif type == 'msteams' %}
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
{% endif %}
