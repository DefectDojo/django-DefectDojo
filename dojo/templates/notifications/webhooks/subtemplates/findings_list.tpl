{% load display_tags %}
{% for finding in findings %}
{% url 'view_finding' finding.id as finding_url %}
    - id: {{ finding.pk }}
      title: {{ finding.title | default_if_none:'' }}
      severity: {{ finding.severity | default_if_none:'' }}
      url: {{ finding_url|full_url }}
{% empty %}
    []
{% endfor %}
