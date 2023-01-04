{% load i18n %}
{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "{% trans "Product Type Added" %}",
    "summary": "{% trans "Product Type Added" %}",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "{% trans "A new product type has been added" %}.",
            "facts": [
                {
                    "name": "{% trans "Product Type" %}:",
                    "value": "{{ title }}"
                }
            ]
        }
        {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
            ,{
                "activityTitle": "{% trans "Disclaimer" %}",
                "text": "{{ system_settings.disclaimer }}"
            }
        {% endif %}
    ],
    "potentialAction": [
        {
            "@type": "OpenUri",
            "name": "{% trans "View Product Type" %}",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
