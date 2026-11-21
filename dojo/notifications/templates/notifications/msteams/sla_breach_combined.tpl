{% load i18n %}{% load display_tags %}{% url 'view_product' product.id as product_url %}
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
                        "text": "{{ title }}",
                        "weight": "Bolder",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "TextBlock",
                        "text": "{% if breach_kind == 'breached' %}{% trans 'These security findings have breached their SLA:' %}{% elif breach_kind == 'prebreach' %}{% trans 'These security findings are about to breach their SLA:' %}{% elif breach_kind == 'breaching' %}{% trans 'These security findings are breaching their SLA today:' %}{% endif %}",
                        "wrap": true
                    }{% for f in findings|slice:":50" %}{% url 'view_finding' f.id as finding_url %},
                    {
                        "type": "TextBlock",
                        "text": "- [{{ f.title }}]({{ finding_url|full_url }}) ({{ f.severity }}), {% trans 'SLA age' %}: {{ f.sla_age }}",
                        "wrap": true,
                        "spacing": "None"
                    }{% endfor %}{% if findings|length > 50 %},
                    {
                        "type": "TextBlock",
                        "text": "{% blocktranslate trimmed with count=findings|length|add:'-50' %}...and {{ count }} more.{% endblocktranslate %}",
                        "wrap": true
                    }{% endif %}{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %},
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
                        "title": "{% trans 'View Product' %}",
                        "url": "{{ product_url|full_url }}"
                    }
                ]
            }
        }
    ]
}
