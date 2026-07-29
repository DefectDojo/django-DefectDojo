{% load display_tags %}
{% load as_json %}
{% include 'notifications/webhooks/subtemplates/base.tpl' %}
{% include 'notifications/webhooks/subtemplates/test.tpl' with test=finding.test %}
{% url 'view_finding' finding.id as finding_url_ui %}
{% url 'finding-detail' finding.id as finding_url_api %}
finding:
    id: {{ finding.pk }}
    title: {{ finding.title | as_json_no_html_esc }}
    severity: {{ finding.severity | as_json_no_html_esc }}
    url_ui: {{ finding_url_ui | full_url | as_json_no_html_esc }}
    url_api: {{ finding_url_api | full_url | as_json_no_html_esc }}
{% if requested_by %}
requested_by:
    id: {{ requested_by.pk }}
    username: {{ requested_by.username | as_json_no_html_esc }}
    first_name: {{ requested_by.first_name | as_json_no_html_esc }}
    last_name: {{ requested_by.last_name | as_json_no_html_esc }}
{% else %}
requested_by: {{ requested_by | as_json_no_html_esc }}
{% endif %}
reviewers:
{% for reviewer in reviewers %}
    - id: {{ reviewer.pk }}
      username: {{ reviewer.username | as_json_no_html_esc }}
      first_name: {{ reviewer.first_name | as_json_no_html_esc }}
      last_name: {{ reviewer.last_name | as_json_no_html_esc }}
{% empty %}
    []
{% endfor %}
