{% load i18n %}{% load display_tags %}
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
                                        "text": "{% trans 'Event' %}",
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
                        "text": "{% autoescape on %}{{ description }}{% endautoescape %}",
                        "wrap": true,
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
                        "title": "{% trans 'View' %}",
                        "url": "{{ url|full_url }}"
                    }
                ]
            }
        }
    ]
}