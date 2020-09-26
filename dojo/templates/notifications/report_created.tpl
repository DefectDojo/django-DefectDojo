{% if type == 'mail' %}
    Greetings,

    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    Your report "{{ report.name }}" is ready.
{% elif type == 'slack' %}
    Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url }}
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": "0072C6",
        "title": "Report created",
        "text": "Your report "{{ report.name }}" is ready.",
        "potentialAction": [
            {
            "@type": "OpenUri",
            "name": "Download",
            "targets": [
                { "os": "default", "uri": "{{ url }}" }
                ]
            }
        ]
    }
{% endif %}