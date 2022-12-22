{{ description }}

{% if risk_acceptance.is_expired %}
    Risk Acceptance Expired
{% else %}
    Risk Acceptance Will Expire Soon
{% endif %}

Risk Acceptance can be viewed here: {{ risk_acceptance_url|full_url }}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
