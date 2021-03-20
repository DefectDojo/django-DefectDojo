{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_test' finding.test.id as test_url %}
{% url 'view_finding' finding.id as finding_url %}
*Title*: [{{ finding.title|jiraencode}}|{{ finding_url|full_url }}]

*Defect Dojo link:* {{ finding_url|full_url }} ({{ finding.id }})

*Severity:* {{ finding.severity }}
{% if finding.cwe > 0 %}
*CWE:* [CWE-{{ finding.cwe }}|{{ finding.cwe|cwe_url }}]
{% else %}
*CWE:* Unknown
{% endif %}

{% if finding.cve %}
*CVE:* [{{ finding.cve }}|{{ finding.cve|cve_url }}]
{% else %}
*CVE:* Unknown
{% endif %}

*Product/Engagement/Test:* [{{ finding.test.engagement.product.name }}|{{ product_url|full_url }}] / [{{ finding.test.engagement.name }}|{{ engagement_url|full_url }}] / [{{ finding.test }}|{{ test_url|full_url }}]

*Branch/Tag:* {{ finding.test.engagement.branch_tag }}

*BuildID:* {{ finding.test.engagement.build_id }}

*Commit hash:* {{ finding.test.engagement.commit_hash }}

{% if finding.endpoints.all %}
*Systems/Endpoints*:
{% for endpoint in finding.endpoints.all %}
* {{ endpoint }}{% endfor %}
{% comment %}
    we leave the endfor at the same line to avoid double line breaks i.e. too many blank lines
{% endcomment %}
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
