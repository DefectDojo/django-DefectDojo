{% load display_tags %}
{% for finding in findings %}
{% url 'view_finding' finding.id as finding_url_ui %}
{% url 'finding-detail' finding.id as finding_url_api %}
    - id: {{ finding.pk }}
      title: {{ finding.title | default_if_none:'' }}
      severity: {{ finding.severity | default_if_none:'' }}
      url_ui: {{ finding_url_ui|full_url }}
      url_api: {{ finding_url_api|full_url }}
{% empty %}
    []
{% endfor %}
