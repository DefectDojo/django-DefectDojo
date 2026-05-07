{% load i18n %}{% load display_tags %}{% url 'view_test' test.id as url %}
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
                                        "text": "{% trans 'Scan Added' %}",
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
                        "text": "{% blocktranslate with count=finding_count %}{{ count }} findings have been updated for scan{% endblocktranslate %} [{{ test }}]({{ url|full_url }}).",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "{% trans 'Product' %}:",
                                "value": "{{ test.engagement.product.name }}"
                            },
                            {
                                "title": "{% trans 'Engagement' %}:",
                                "value": "{{ test.engagement.name }}"
                            },
                            {
                                "title": "{% trans 'Scan' %}:",
                                "value": "{{ test }}"
                            },
                            {
                                "title": "{% trans 'Scan Type' %}:",
                                "value": "{{ test.test_type.name }}"
                            },
                            {
                                "title": "{% trans 'Updated Findings' %}:",
                                "value": "{{ finding_count }}"
                            },
                            {
                                "title": "{% trans 'New Findings' %}:",
                                "value": "{{ findings_new|length|default:'0' }}"
                            },
                            {
                                "title": "{% trans 'Reactivated Findings' %}:",
                                "value": "{{ findings_reactivated|length|default:'0' }}"
                            },
                            {
                                "title": "{% trans 'Closed Findings' %}:",
                                "value": "{{ findings_mitigated|length|default:'0' }}"
                            },
                            {
                                "title": "{% trans 'Untouched Findings' %}:",
                                "value": "{{ findings_untouched|length|default:'0' }}"
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
                        "title": "{% trans 'View Scan' %}",
                        "url": "{{ url|full_url }}"
                    }
                ]
            }
        }
    ]
}