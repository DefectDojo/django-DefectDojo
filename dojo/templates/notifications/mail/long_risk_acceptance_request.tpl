{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% load static %}
{% url 'view_risk_acceptance' risk_acceptance.engagement.id risk_acceptance.id as risk_acceptance_url %}
{% url 'view_product' risk_acceptance.engagement.product.id as product_url %}
{% url 'view_engagement' risk_acceptance.engagement.id as engagement_url %}

{% url 'view_long_risk_acceptance_details' long_risk_acceptance.id as long_ra_url %}

{% block content%}
	

	{% block contect_description %}
		
		{% if long_risk_acceptance.description %}
			<p style="color: #555; line-height: 1.6;">{{ long_risk_acceptance.description }}</p>
		{% endif %}
	{% endblock %}

	{% block risk_evaluation %}
	<div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107;">
	{% for risk in long_risk_acceptance.riskacceptanceengagementeconomicimpact_set.all %}
		<p style="margin: 8px 0; padding-left: 10px; border-left: 2px solid #ffc107; color: #555;">
			<strong>Title:</strong> {{ risk.title }}</br>
			<strong>Description:</strong> {{ risk.description }}<br/>
			<strong>Control Effectiveness:</strong> {{ risk.control_effectiveness }}%<br/>
			<strong>Economic Impact:</strong> {{ risk.economic_impact }} MM<br/>
		</p>
	{% endfor %}
	</div>
	{% endblock %}

	{% block risk %}
		<div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107;">
			{% if long_risk_acceptance.risk_level == "VERY CRITICAL" %}
			<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Risk Level:{% endblocktranslate %}</strong> <span style="color: #aa0a0a;">{{ long_risk_acceptance.risk_level }} ◉ </span></p>
			{% elif long_risk_acceptance.risk_level == "CRITICAL" %}
			<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Risk Level:{% endblocktranslate %}</strong> <span style="color: #c05e1d;">{{ long_risk_acceptance.risk_level }} ◉ </span></p>
			{% elif long_risk_acceptance.risk_level == "MODERATE" %}
			<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Risk Level:{% endblocktranslate %}</strong> <span style="color: #b4b218;">{{ long_risk_acceptance.risk_level }} ◉ </span></p>
			{% elif long_risk_acceptance.risk_level == "TOLERABLE" %}
			<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Risk Level:{% endblocktranslate %}</strong> <span style="color: #258308;">{{ long_risk_acceptance.risk_level }} ◉ </span></p>
			{% endif %}

			<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Status:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.risk_status }}</span></p>
			
			{% if long_risk_acceptance.product %}
				<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Product:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.product.name }}</span></p>
			{% endif %}
			
			{% if long_risk_acceptance.owner %}
				<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Owner:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.owner.username }}</span></p>
			{% endif %}
			
			<div style="background-color: #f0f0f0; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107; margin-top: 15px;">
				<p style="margin: 0; color: #333;"><strong>{% blocktranslate %}Total Affected Findings:{% endblocktranslate %}</strong> <span style="color: #d9534f; font-size: 18px; font-weight: bold;">{{ findings_count|default:"0" }}</span></p>
			</div>

			<div style="background-color: #f0f0f0; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107; margin-top: 15px;">
				<h4 style="color: #333; margin-top: 0; margin-bottom: 10px;">{% blocktranslate %}Engagements:{% endblocktranslate %}</h4>
				{% if long_risk_acceptance.engagement_set.all %}
					{% for engagement in long_risk_acceptance.engagement_set.all %}
						<p style="margin: 8px 0; padding-left: 10px; border-left: 2px solid #ffc107; color: #555;">
							<br/>
							• <strong>{{ engagement.name }}</strong>
							<br/>
						</p>
					{% endfor %}
				{% else %}
					<p style="color: #999; margin: 0;">{% blocktranslate %}No engagements associated{% endblocktranslate %}</p>
				{% endif %}
			</div>
		</div>
	{% endblock %}

{% block event %}
		<br/>
		<br/>
		More information on this event can be found here:
		{% blocktranslate trimmed with event_url=url|full_url %}
		<center><a href="{{event_url}}" class="proton-button" target="_blank">Go Long Risk Acceptance</a></center>
		{% endblocktranslate %}
	{% endblock%}
{% endblock %}