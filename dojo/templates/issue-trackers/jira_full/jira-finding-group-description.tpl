{% load navigation_tags %}
{% load display_tags %}
{% url 'view_finding_group' finding_group.id as finding_group_url %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_test' finding.test.id as test_url %}

A group of Findings has been pushed to JIRA to be investigated and fixed:

h2. Group
*Group*: [{{ finding_group.name|jiraencode}}|{{ finding_group_url|full_url }}] in [{{ finding_group.test.engagement.product.name|jiraencode }}|{{ product_url|full_url }}] / [{{ finding_group.test.engagement.name|jiraencode }}|{{ engagement_url|full_url }}] / [{{ finding_group.test|stringformat:'s'|jiraencode }}|{{ test_url|full_url }}]


|| Severity || CVE || CWE || Component || Version || Title || Status ||{% for finding in finding_group.findings.all %}
| {{finding.severity}} | {% if finding.cve %}[{{finding.cve}}|{{finding.cve|cve_url}}]{% else %}None{% endif %} | [{{finding.cwe}}|{{finding.cwe|cwe_url}}] | {{finding.component_name|jiraencode_component}} | {{finding.component_version}} | [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}] | {{ finding.status }} |{% endfor %}

*Branch/Tag:* {{ finding_group.test.engagement.branch_tag }}

*BuildID:* {{ finding_group.test.engagement.build_id }}

*Commit hash:* {{ finding_group.test.engagement.commit_hash }}


{% for finding in finding_group.findings.all %}
{% url 'view_finding' finding.id as finding_url %}

h1. Findings

h3. [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]
*Defect Dojo link:* {{ finding_url|full_url }} ({{ finding.id }})
*Severity:* {{ finding.severity }}
{% if finding.cwe > 0 %}*CWE:* [CWE-{{ finding.cwe }}|{{ finding.cwe|cwe_url }}]{% else %}*CWE:* Unknown{% endif %}
{% if finding.cve %}*CVE:* [{{ finding.cve }}|{{ finding.cve|cve_url }}]{% else %}*CVE:* Unknown{% endif %}

{% if finding.endpoints.all %}
*Systems/Endpoints*:
{% for endpoint in finding.endpoints.all %}
* {{ endpoint }}{% endfor %}
{%endif%}

{% if finding.component_name %}
Vulnerable Component: {{finding.component_name }} - {{ finding.component_version }}

{% endif %}
{% if finding.sast_source_object %}
Source Object: {{ finding.sast_source_object }}
Source File: {{ finding.sast_source_file_path }}
Source Line: {{ finding.sast_source_line }}
Sink Object: {{ finding.sast_sink_object }}
{% endif %}

*Description*:
{{ finding.description }}

*Mitigation*:
{{ finding.mitigation }}

*Impact*:
{{ finding.impact }}

*Steps to reproduce*:
{{ finding.steps_to_reproduce }}

*References*:
{{ finding.references }}

*Reporter:* [{{ finding.reporter|full_name}} ({{ finding.reporter.email }})|mailto:{{ finding.reporter.email }}]
{% endfor %}