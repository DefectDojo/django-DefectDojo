The engagement "{{ engagement.product }}" is starting on {{ engagement.target_start }}.
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
