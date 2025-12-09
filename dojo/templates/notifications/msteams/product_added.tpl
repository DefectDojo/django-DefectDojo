{% load i18n %}{% load display_tags %}{% url 'view_product' product.id as url %}
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
                                        "text": "{% trans 'Product Added' %}",
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
                        "text": "{% trans 'A new product' %} [{{ product.name }}]({{ url|full_url }}) {% trans 'has been added.' %}",
                        "wrap": true,
                        "spacing": "Medium"
                    },
                    {
                        "type": "FactSet",
                        "facts": [
                            {
                                "title": "{% trans 'Product' %}:",
                                "value": "{{ product.name }}"
                            },
                            {
                                "title": "{% trans 'Tags' %}:",
                                "value": "{% for tag in product.tags.all %}{{ tag.name }}{% if not forloop.last %}, {% endif %}{% empty %}{% trans 'None' %}{% endfor %}"
                            },
                            {
                                "title": "{% trans 'Product Type' %}:",
                                "value": "{{ product.prod_type.name }}"
                            },
                            {
                                "title": "{% trans 'SLA Configuration' %}:",
                                "value": "{% if product.sla_configuration %}{{ product.sla_configuration.name }}{% else %}{% trans 'None' %}{% endif %}"
                            },
                            {
                                "title": "{% trans 'Internet Accessible' %}:",
                                "value": "{% if product.internet %}{% trans 'Yes' %}{% else %}{% trans 'No' %}{% endif %}"
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
                        "title": "{% trans 'View Product' %}",
                        "url": "{{ url|full_url }}"
                    }
                ]
            }
        }
    ]
}