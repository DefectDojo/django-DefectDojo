{% load i18n %}
{{ description }}
{% if url is not None %}
    
  {% blocktranslate trimmed with scan_url=url|full_url %}
    {{ test }} results have been uploaded.
    They can be viewed here: {{ scan_url }}
  {% endblocktranslate %}
{% endif %}
{% if system_settings.disclaimer and system_settings.disclaimer.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer }}
{% endif %}
