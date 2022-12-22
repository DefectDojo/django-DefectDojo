{
    "@context": "https://schema.org/extensions",
    "@type": "MessageCard",
    "title": "Product Added",
    "summary": "Product Added",
    "sections": [
        {
            "activityTitle": "DefectDojo",
            "activityImage": "https://raw.githubusercontent.com/DefectDojo/django-DefectDojo/master/dojo/static/dojo/img/chop.png",
            "text": "A new product has been added.",
            "facts": [
                {
                    "name": "Product:",
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
            "name": "View Product",
            "targets": [
                {
                    "os": "default",
                    "uri": "{{ url|full_url }}"
                }
            ]
        }
    ]
}
