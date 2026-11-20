{% load i18n %}{% load display_tags %}{% url 'view_product' product.id as product_url %}*{{ title }}*
{% if breach_kind == 'breached' %}{% trans "These security findings have breached their SLA:" %}{% elif breach_kind == 'prebreach' %}{% trans "These security findings are about to breach their SLA:" %}{% elif breach_kind == 'breaching' %}{% trans "These security findings are breaching their SLA today:" %}{% endif %}
{% for f in findings|slice:":50" %}{% url 'view_finding' f.id as finding_url %}• <{{ finding_url|full_url }}|{{ f.title }}> ({{ f.severity }}), {% trans "SLA age" %}: {{ f.sla_age }}
{% endfor %}{% if findings|length > 50 %}{% blocktranslate trimmed with count=findings|length|add:"-50" %}...and {{ count }} more.{% endblocktranslate %}
{% endif %}{% blocktranslate trimmed with name=product.name url=product_url|full_url %}Product {{ name }}: {{ url }}{% endblocktranslate %}
{% if system_settings.disclaimer_notifications and system_settings.disclaimer_notifications.strip %}
{% trans "Disclaimer" %}:
{{ system_settings.disclaimer_notifications }}
{% endif %}
