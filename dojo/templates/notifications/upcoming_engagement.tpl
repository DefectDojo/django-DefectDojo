{% if type == 'mail' %}
    Hello,

    this is a reminder that the engagement "{{ engagement.product }}" is about to start shortly.
    
    Project start: {{ engagement.target_start }}
    Project end: {{ engagement.target_end }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}.
{% elif type == 'slack' %}
    The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}.
{% elif type == 'msteams' %}
    {
        "@context": "https://schema.org/extensions",
        "@type": "MessageCard",
        "themeColor": "0072C6",
        "title": "Engagement added",
        "text": "The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}."
    }
{% endif %}