{% load i18n %}{% blocktranslate trimmed with finding_id=finding.id %}
SLA breach alert for finding {{ finding_id }}. Relative days count to SLA due date: {{sla_age}}.
{% endblocktranslate %}