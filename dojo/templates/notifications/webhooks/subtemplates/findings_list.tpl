{% load display_tags %}
{% for finding in findings %}
{% url 'view_finding' finding.id as finding_url %}
    - id: {{ finding.pk }}
      title: {{ finding.title }}
      severity: {{ finding.severity }}
      url: {{ finding_url|full_url }}
{% else %}
    []
{% endfor %}
