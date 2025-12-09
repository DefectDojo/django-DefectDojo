{% load i18n %}{% load display_tags %}{% url 'view_finding' finding.id as finding_url %}
{
    "type": "message",
    "attachments": [
        {
            "contentType": "application/vnd.microsoft.card.adaptive",
            "content": {
                "$schema": "http://adaptivecards.io/schemas/adaptive-card.json",
                "type": "AdaptiveCard",
                "version": "1.4",
                "body": [
                    {
                        "type": "ColumnSet",
                        "columns": [
                            {
                                "type": "Column",
                                "width": "auto",
                                "items": [
                                    {
                                        "type": "Image",
                                        "url": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
                                        "size": "Small"
                                    }
                                ]
                            },
                            {
                                "type": "Column",
                                "width": "stretch",
                                "items": [
                                    {
                                        "type": "TextBlock",
                                        "text": "DefectDojo",
                                        "weight": "Bolder",
                                        "size": "Medium"
                                    },
                                    {
                                        "type": "TextBlock",
                                        "text": "{% trans 'SLA Breach' %}",
                                        "weight": "Bolder",
                                        "size": "Large",
                                        "color": "Accent"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": "{% trans 'SLA breach' %} [{{ finding.title }}]({{ finding_url|full_url }}) {% blocktranslate with severity=finding.severity sla_age=sla_age %}with severity {{ severity }} has breached its SLA ({{ sla_age }} days).{% endblocktranslate %}",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "{% trans 'Product' %}:",
                                "value": "{{ finding.test.engagement.product.name }}"
                            },
                            {
                                "title": "{% trans 'Engagement' %}:",
                                "value": "{{ finding.test.engagement.name }}"
                            },
                            {
                                "title": "{% trans 'Finding' %}:",
                                "value": "{{ finding.title }}"
                            },
                            {
                                "title": "{% trans 'Severity' %}:",
                                "value": "{{ finding.severity }}"
                            },
                            {
                                "title": "{% trans 'SLA age' %}:",
                                "value": "{{ sla_age }} days"
                            }
                        ],
                        "spacing": "Medium"
                    }{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %},
                    {
                        "type": "Container",
                        "style": "attention",
                        "items": [
                            {
                                "type": "TextBlock",
                                "text": "{% trans 'Disclaimer' %}",
                                "weight": "Bolder"
                            },
                            {
                                "type": "TextBlock",
                                "text": "{{ system_settings.disclaimer_notifications }}",
                                "wrap": true
                            }
                        ],
                        "spacing": "Medium"
                    }{% endif %}
                ],
                "actions": [
                    {
                        "type": "Action.OpenUrl",
                        "title": "{% trans 'View Finding' %}",
                        "url": "{{ finding_url|full_url }}"
                    }
                ]
            }
        }
    ]
}