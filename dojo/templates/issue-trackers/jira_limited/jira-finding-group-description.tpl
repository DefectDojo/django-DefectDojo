{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding_group' finding_group.id as finding_group_url %}
{% url 'view_product' finding_group.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding_group.test.engagement.id as engagement_url %}
{% url 'view_test' finding_group.test.id as test_url %}

A group of Findings has been pushed to JIRA to be investigated and fixed:

*Group*: [{{ finding_group.name|jiraencode}}|{{ finding_group_url|full_url }}] in [{{ finding_group.test.engagement.product.name|jiraencode }}|{{ product_url|full_url }}] / [{{ finding_group.test.engagement.name|jiraencode }}|{{ engagement_url|full_url }}] / [{{ finding_group.test|stringformat:'s'|jiraencode }}|{{ test_url|full_url }}]

Findings:
{% for finding in finding_group.findings.all %}
{% url 'view_finding' finding.id as finding_url %}
- [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]{% endfor %}

{% if finding_group.test.engagement.branch_tag %}
*Branch/Tag:* {{ finding_group.test.engagement.branch_tag }}
{% endif %}

{% if finding_group.test.engagement.build_id %}
*BuildID:* {{ finding_group.test.engagement.build_id }}
{% endif %}

{% if finding_group.test.engagement.commit_hash %}
*Commit hash:* {{ finding_group.test.engagement.commit_hash }}
{% endif %}
