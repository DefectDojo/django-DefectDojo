{% load i18n %}
{% load display_tags %}
{{ description }}

{% if risk_acceptances %}
{{ title }}
{% for each in risk_acceptances %}{% url 'view_risk_acceptance' each.engagement.id each.id as each_url %}
- {{ each }}: {{ each_url|full_url }}{% endfor %}
{% else %}
{% if risk_acceptance.is_expired %}
    {% trans "Risk Acceptance Expired" %}
{% else %}
    {% trans "Risk Acceptance Will Expire Soon" %}
{% endif %}

{% blocktranslate trimmed with risk_url=url|full_url %}
Risk Acceptance can be viewed here: {{ risk_url }}
{% endblocktranslate %}
{% endif %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
    
    {% trans "Disclaimer" %}:
    {{ system_settings.disclaimer_notifications }}
{% endif %}
