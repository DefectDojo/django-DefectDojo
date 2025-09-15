{% load i18n %}{% load display_tags %}{% url 'view_risk_acceptance' risk_acceptance.id as url %}
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
                                        "text": "{% if risk_acceptance.is_expired %}{% trans 'Risk Acceptance Expired' %}{% else %}{% trans 'Risk Acceptance Expiring' %}{% endif %}",
                                        "weight": "Bolder",
                                        "size": "Large",
                                        "color": "{% if risk_acceptance.is_expired %}Attention{% else %}Warning{% endif %}"
                                    }
                                ]
                            }
                        ]
                    },
                    {
                        "type": "TextBlock",
                        "text": "{% if risk_acceptance.is_expired %}{% trans 'Risk acceptance' %} [{{ risk_acceptance }}]({{ url|full_url }}) {% blocktranslate with risk_findings=risk_acceptance.accepted_findings.all|length risk_date=risk_acceptance.expiration_date_handled|date %}with {{ risk_findings }} finding(s) has expired on {{ risk_date }}.{% endblocktranslate %}{% else %}{% trans 'Risk acceptance' %} [{{ risk_acceptance }}]({{ url|full_url }}) {% blocktranslate with risk_findings=risk_acceptance.accepted_findings.all|length risk_date=risk_acceptance.expiration_date|date %}with {{ risk_findings }} finding(s) will expire on {{ risk_date }}.{% endblocktranslate %}{% endif %}",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "{% trans 'Risk Acceptance' %}:",
                                "value": "{{ risk_acceptance }}"
                            },
                            {
                                "title": "{% trans 'Accepted Findings' %}:",
                                "value": "{{ risk_acceptance.accepted_findings.all|length }}"
                            },
                            {
                                "title": "{% if risk_acceptance.is_expired %}{% trans 'Expired Date' %}{% else %}{% trans 'Expiration Date' %}{% endif %}:",
                                "value": "{% if risk_acceptance.is_expired %}{{ risk_acceptance.expiration_date_handled|date }}{% else %}{{ risk_acceptance.expiration_date|date }}{% endif %}"
                            }{% if risk_acceptance.reactivate_expired %},
                            {
                                "title": "{% trans 'Reactivation Status' %}:",
                                "value": "{% trans 'Findings have been reactivated' %}"
                            }{% endif %}{% if risk_acceptance.restart_sla_expired %},
                            {
                                "title": "{% trans 'SLA Status' %}:",
                                "value": "{% trans 'Findings SLA start date have been reset' %}"
                            }{% endif %}
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
                        "title": "{% trans 'View Risk Acceptance' %}",
                        "url": "{{ url|full_url }}"
                    }
                ]
            }
        }
    ]
}