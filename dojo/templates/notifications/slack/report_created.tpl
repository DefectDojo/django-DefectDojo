Your report "{{ report.name }}" is ready. It can be downloaded here: {{ url|full_url }}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
