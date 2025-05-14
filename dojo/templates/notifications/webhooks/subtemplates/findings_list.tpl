{% load display_tags %}
{% load as_json %}
{% for finding in findings %}
{% url 'view_finding' finding.id as finding_url_ui %}
{% url 'finding-detail' finding.id as finding_url_api %}
    - id: {{ finding.pk }}
      title: {{ finding.title | as_json_no_html_esc }}
      severity: {{ finding.severity | as_json_no_html_esc }}
      url_ui: {{ finding_url_ui | full_url | as_json_no_html_esc }}
      url_api: {{ finding_url_api | full_url | as_json_no_html_esc }}
{% empty %}
    []
{% endfor %}
