The new product type "{{ title }}" has been added. It can be viewed here: {{ url|full_url }}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
