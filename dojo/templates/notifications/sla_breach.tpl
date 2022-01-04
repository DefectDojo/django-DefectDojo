{% if type == 'mail' %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding' finding.id as finding_url %}
    <html>
        <body>
            {% autoescape on %}
                <p>
                    Hello {{ user.get_full_name }},
                </p>
                <br/>
                <br/>
                <p>
                    {% if sla_age < 0 %}
                        This security finding has breached its SLA.
                        
                        - Day(s) overdue: {{sla}}
                    {% else %}
                        A security finding is about to breach its SLA.
                        
                        - Day(s) remaining: {{sla}}
                    {% endif %}
                </p>
                    <br/>
                    - Title: <a href="{{finding_url|full_url}}">{{finding.title}}</a>
                    <br/>
                    - Severity: {{finding.severity}}
                    <br/><br/>
                    Please refer to your SLA documentation for further guidance
                </p>
                <br/></br>
                Kind regards,
                </br></br>
                {% if system_settings.team_name %}
                    {{ system_settings.team_name }}
                {% else %}
                    Defect Dojo
                {% endif %}
                <br/><br/>
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
    SLA breach alert for finding {{ finding.id }}. Relative days count to SLA due date: {{sla_age}}.
{% elif type == 'slack' %}
    SLA breach alert for finding {{ finding.id }}. Relative days count to SLA due date: {{sla_age}}.
    Title: {{finding.title}}
    Severity: {{finding.severity}}
    You can find details here: {{ url|full_url }}
    {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
        
        Disclaimer:
        {{ system_settings.disclaimer }}
    {% endif %}
{% elif type == 'msteams' %}
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
{% endif %}
