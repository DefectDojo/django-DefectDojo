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
| {{finding.severity}} | {% if finding.cve %}[{{finding.cve}}|{{finding.cve|vulnerability_url}}]{% else %}None{% endif %} | [{{finding.cwe}}|{{finding.cwe|cwe_url}}] | {{finding.component_name|jiraencode_component}} | {{finding.component_version}} | [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}] | {{ finding.status }} |{% endfor %}

*Severity:* {{ finding_group.severity }}

{% if finding_group.sla_deadline %} *Due Date:* {{ finding_group.sla_deadline }} {% endif %}

{% if finding_group.test.engagement.branch_tag %}
*Branch/Tag:* {{ finding_group.test.engagement.branch_tag }}
{% endif %}

{% if finding_group.test.engagement.build_id %}
*BuildID:* {{ finding_group.test.engagement.build_id }}
{% endif %}

{% if finding_group.test.engagement.commit_hash %}
*Commit hash:* {{ finding_group.test.engagement.commit_hash }}
{% endif %}

{% for finding in finding_group.findings.all %}
{% url 'view_finding' finding.id as finding_url %}

h1. Findings

h3. [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]
*Defect Dojo link:* {{ finding_url|full_url }} ({{ finding.id }})
*Severity:* {{ finding.severity }}
{% if finding.sla_deadline %} *Due Date:* {{ finding.sla_deadline }} {% endif %}
{% if finding.cwe > 0 %} *CWE:* [CWE-{{ finding.cwe }}|{{ finding.cwe|cwe_url }}] {% endif %}
{% if finding.cve %}*CVE:* [{{ finding.cve }}|{{ finding.cve|vulnerability_url }}]{% else %}*CVE:* Unknown{% endif %}
{% if finding.cvssv3_score %} *CVSSv3 Score:* {{ finding.cvssv3_score }} {% endif %}

{% if finding.endpoints.all %}
*Systems/Endpoints*:
{% for endpoint in finding.endpoints.all %}
* {{ endpoint }}{% endfor %}
{%endif%}

{% if finding.sast_source_object %}
*Source Object*: {{ finding.sast_source_object }}
*Source File*: {{ finding.sast_source_file_path }}
*Source Line*: {{ finding.sast_source_line }}
*Sink Object*: {{ finding.sast_sink_object }}
{% elif finding.static_finding %}
{% if finding.file_path %}
*Source File*: {{ finding.file_path }}
{% endif %}
{% if finding.line %}
*Source Line*: {{ finding.line }}
{% endif %}
{% endif %}

*Description*:
{{ finding.description }}

{% if finding.mitigation %}
*Mitigation*:
{{ finding.mitigation }}
{% endif %}

{% if finding.impact %}
*Impact*:
{{ finding.impact }}
{% endif %}

{% if finding.steps_to_reproduce %}
*Steps to reproduce*:
{{ finding.steps_to_reproduce }}
{% endif %}

{% if finding.references %}
*References*:
{{ finding.references }}
{% endif %}

*Reporter:* [{{ finding.reporter|full_name}} ({{ finding.reporter.email }})|mailto:{{ finding.reporter.email }}]
{% endfor %}