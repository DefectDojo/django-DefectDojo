{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% load static %}
{% url 'view_risk_acceptance' risk_acceptance.engagement.id risk_acceptance.id as risk_acceptance_url %}
{% url 'view_product' risk_acceptance.engagement.product.id as product_url %}
{% url 'view_engagement' risk_acceptance.engagement.id as engagement_url %}
{% block content%}
	{%block risk %}
		{% if risk_acceptance.is_expired %}
			{% blocktranslate with risk_url=risk_acceptance_url|full_url risk_findings=risk_acceptance.accepted_findings.all|length risk_date=risk_acceptance.expiration_date_handled|date %}<a href="{{risk_url}}">Risk acceptance {{ risk_acceptance }}</a> with {{ risk_findings }} findings has expired {{ risk_date }}{% endblocktranslate %}
		{% else %}
			{% blocktranslate with risk_url=risk_acceptance_url|full_url risk_findings=risk_acceptance.accepted_findings.all|length risk_date=risk_acceptance.expiration_date|date %}<a href="{{risk_url}}">Risk acceptance {{ risk_acceptance }}</a> with {{ risk_findings }} findings will expire {{ risk_date }}{% endblocktranslate %}
		{% endif %}
		{% if risk_acceptance.reactivate_expired %}
			{% blocktranslate %}Findings have been reactivated</p>{% endblocktranslate %}
		{% endif %}
		{% if risk_acceptance.restart_sla_expired %}
			{% blocktranslate %}Findings SLA start date have been reset</p>{% endblocktranslate %}
		{% endif %}
	{%endblock%}
		<br/>
		{%block findings%}
			{% for finding in risk_acceptance.accepted_findings.all %}
				{% url 'view_finding' finding.id as finding_url %}
				<a href="{{ finding_url|full_url }}">{{ finding.title }}</a> ({{ finding.severity }}) {{ finding.status }}
			{% endfor %}
			<br/>
		{%endblock%}
	
	{% block event %}
		<br/>
		<br/>
		More information on this event can be found here:
		{% blocktranslate trimmed with event_url=url|full_url %}
		<center><a href="{{event_url}}" class="proton-button" target="_blank">Go Risk Acceptance</a></center>
		{% endblocktranslate %}
	{% endblock%}

	{%block acceptance_for_url%}
		<br/>
		<br/>
		If for some reason you can not enter vultacker you have the option to accept it directly. if you click on the following link
			{% for permission_key in permission_keys %}
				{% if permission_key.username == user.username%}
				<a href="{{permission_key.url}}" >Accept all risks</a>
				{% endif %}
			{% endfor %}
	{%endblock%}

{%endblock%}
