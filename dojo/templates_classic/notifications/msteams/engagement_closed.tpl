{% load i18n %}{% load display_tags %}{% url 'view_engagement' engagement.id as url %}
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
                                        "text": "{% trans 'Engagement Closed' %}",
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
                        "text": "{% trans 'An engagement' %} [{{ engagement.name }}]({{ url|full_url }}) {% trans 'has been closed.' %}",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "{% trans 'Product' %}:",
                                "value": "{{ engagement.product.name }}"
                            },
                            {
                                "title": "{% trans 'Engagement' %}:",
                                "value": "{{ engagement.name }}"
                            },
                            {
                                "title": "{% trans 'Start date' %}:",
                                "value": "{{ engagement.target_start }}"
                            },
                            {
                                "title": "{% trans 'End date' %}:",
                                "value": "{{ engagement.target_end }}"
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
                        "title": "{% trans 'View Engagement' %}",
                        "url": "{{ url|full_url }}"
                    }
                ]
            }
        }
    ]
}