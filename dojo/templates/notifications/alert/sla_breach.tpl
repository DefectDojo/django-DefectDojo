{% load i18n %}{% blocktranslate trimmed with finding_id=finding.id product_name=finding.test.engagement.product %}
SLA breach alert for finding {{ finding_id }} in product {{ product_name }}. Relative days count to SLA due date: {{sla_age}}.
{% endblocktranslate %}