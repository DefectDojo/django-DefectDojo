{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_test' finding.test.id as test_url %}
{% url 'view_finding' finding.id as finding_url %}

*Defect Dojo link:* {{ finding_url|full_url }} ({{ finding.id }})

*Product/Engagement/Test:* [{{ finding.test.engagement.product.name }}|{{ product_url|full_url }}] / [{{ finding.test.engagement.name }}|{{ engagement_url|full_url }}] / [{{ finding.test }}|{{ test_url|full_url }}]

*Reporter:* [{{ finding.reporter|full_name}} ({{ finding.reporter.email }})|mailto:{{ finding.reporter.email }}]