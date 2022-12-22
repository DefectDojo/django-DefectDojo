User {{ user }} jotted a note on {{ section }}:

{{ note }}

Full details of the note can be reviewed at {{ url }}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    Disclaimer:
    {{ system_settings.disclaimer }}
{% endif %}
