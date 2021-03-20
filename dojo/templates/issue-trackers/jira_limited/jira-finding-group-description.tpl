{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding_group' finding_group.id as finding_group_url %}
*Name*: [{{ finding_group.name|jiraencode}}|{{ finding_url|full_url }}]
