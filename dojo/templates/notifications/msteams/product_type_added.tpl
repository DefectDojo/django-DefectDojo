{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "Product Type Added",
    "summary": "Product Type Added",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "A new product type has been added.",
            "facts": [
                {
                    "name": "Product Type:",
                    "value": "{{ title }}"
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
            "name": "View Product Type",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
