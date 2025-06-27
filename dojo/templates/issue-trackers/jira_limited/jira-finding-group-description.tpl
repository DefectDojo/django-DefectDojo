{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding_group' finding_group.id as finding_group_url %}
{% url 'view_product' finding_group.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding_group.test.engagement.id as engagement_url %}
{% url 'view_test' finding_group.test.id as test_url %}

A group of Findings has been pushed to JIRA to be investigated and fixed:

h2. Group
*Group*: [{{ finding_group.name|jiraencode}}|{{ finding_group_url|full_url }}] in [{{ finding_group.test.engagement.product.name|jiraencode }}|{{ product_url|full_url }}] / [{{ finding_group.test.engagement.name|jiraencode }}|{{ engagement_url|full_url }}] / [{{ finding_group.test|stringformat:'s'|jiraencode }}|{{ test_url|full_url }}]

h2. Summary
*Severity:* {{ finding_group.findings.all | jira_severity }} {% if finding_group.sla_deadline %} *Due Date:* {{ finding_group | jira_sla_deadline }} {% endif %}

Findings matching the Active, Verified and Severity criteria:
{% for finding in finding_group|jira_qualified_findings %}
- [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]{% endfor %}

Findings *not* matching the Active, Verified and Severity criteria:
{% for finding in finding_group|jira_non_qualified_findings %}
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

{% if finding_text %}
*Finding Text*:
{{ finding_text|safe }}
{% endif %}