{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_test' finding.test.id as test_url %}
{% url 'view_finding' finding.id as finding_url %}
*Title*: [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]

*Defect Dojo link:* {{ finding_url|full_url }} ({{ finding.id }})

*Severity:* {{ finding.severity }}

{% if finding.sla_deadline %}
*Due Date:* {{ finding.sla_deadline }}
{% endif %}

{% if finding.cwe > 0 %}
*CWE:* [CWE-{{ finding.cwe }}|{{ finding.cwe|cwe_url }}]
{% endif %}

{% if finding.cve %}
*CVE:* [{{ finding.cve }}|{{ finding.cve|vulnerability_url }}]
{% else %}
*CVE:* Unknown
{% endif %}

{% if finding.cvssv3_score %}
*CVSSv3 Score:* {{ finding.cvssv3_score }}
{% endif %}

*Product/Engagement/Test:* [{{ finding.test.engagement.product.name }}|{{ product_url|full_url }}] / [{{ finding.test.engagement.name }}|{{ engagement_url|full_url }}] / [{{ finding.test }}|{{ test_url|full_url }}]

{% if finding.test.engagement.branch_tag %}
*Branch/Tag:* {{ finding.test.engagement.branch_tag }}
{% endif %}

{% if finding.test.engagement.build_id %}
*BuildID:* {{ finding.test.engagement.build_id }}
{% endif %}

{% if finding.test.engagement.commit_hash %}
*Commit hash:* {{ finding.test.engagement.commit_hash }}
{% endif %}

{% if finding.endpoints.all %}
*Systems/Endpoints*:
{% for endpoint in finding.endpoints.all %}
* {{ endpoint }}{% endfor %}
{% comment %}
    we leave the endfor at the same line to avoid double line breaks i.e. too many blank lines
{% endcomment %}
{%endif%}

{% if finding.component_name %}
*Vulnerable Component*: {{finding.component_name }} - {{ finding.component_version }}
{% endif %}

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
