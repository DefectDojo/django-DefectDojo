{{ description }}
{% if url is not None %}
    
    {{ test }} results have been uploaded.
    They can be viewed here: {{ url|full_url }}
{% endif %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
