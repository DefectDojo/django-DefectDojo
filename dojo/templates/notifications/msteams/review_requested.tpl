{% comment %}
NOTE: This template is currently NOT USED in practice because:
- review_requested notifications are sent to specific recipients (the reviewers)
- Microsoft Teams only supports system-wide notifications, not user-specific ones
- The notification system processes recipient-specific notifications using personal settings
- Since Teams doesn't have individual user channels/usernames (unlike email or Slack),
  these notifications will only work for channels that support user-specific delivery
{% endcomment %}
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
                                        "text": "{% trans 'Review Requested' %}",
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
                        "text": "{% trans 'A review has been requested for finding' %} [{{ finding.title }}]({{ finding_url|full_url }}).",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "TextBlock",
                        "text": "{% trans 'Reviewers:' %} {% for reviewer in reviewers %}{{ reviewer.get_full_name|default:reviewer.username }}{% if not forloop.last %}, {% endif %}{% endfor %}",
                        "wrap": true,
                        "spacing": "Small"
                    },
                    {
                        "type": "TextBlock",
                        "text": "{{ note.entry }}",
                        "wrap": true,
                        "spacing": "Small",
                        "isSubtle": true
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