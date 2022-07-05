{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding_group' finding_group.id as finding_group_url %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_test' finding.test.id as test_url %}

A group of Findings has been pushed to JIRA to be investigated and fixed:

*Group*: [{{ finding_group.name|jiraencode}}|{{ finding_group_url|full_url }}] in [{{ finding_group.test.engagement.product.name|jiraencode }}|{{ product_url|full_url }}] / [{{ finding_group.test.engagement.name|jiraencode }}|{{ engagement_url|full_url }}] / [{{ finding_group.test|stringformat:'s'|jiraencode }}|{{ test_url|full_url }}]

Findings:
{% for finding in finding_group.findings.all %}
- [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]{% endfor %}

*Branch/Tag:* {{ finding_group.test.engagement.branch_tag }}

*BuildID:* {{ finding_group.test.engagement.build_id }}

*Commit hash:* {{ finding_group.test.engagement.commit_hash }}
