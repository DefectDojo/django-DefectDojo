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
		<div style="background-color: #fff3cd; border-left: 4px solid #ffc107; padding: 15px; margin: 15px 0; border-radius: 4px;">
			{% if long_risk_acceptance.expiration_date_handled %}
				{% blocktranslate with expiration_date=long_risk_acceptance.expiration_date_handled|date:"b d, Y H:i" %}
					<strong style="color: #d9534f;">This long-term risk acceptance has EXPIRED on {{ expiration_date }}</strong>
				{% endblocktranslate %}
			{% else %}
				{% blocktranslate with expiration_date=long_risk_acceptance.expiration_date|date:"b d, Y H:i" %}
					<strong style="color: #d9534f;">This long-term risk acceptance will EXPIRE on {{ expiration_date }}</strong>
				{% endblocktranslate %}
			{% endif %}
		</div>
		
		{% if long_risk_acceptance.description %}
			<p style="color: #555; line-height: 1.6;">{{ long_risk_acceptance.description }}</p>
		{% endif %}
	{% endblock %}

	{% block risk %}
		<div style="background-color: #f9f9f9; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107;">
			<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Status:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.status }}</span></p>
			
			{% if long_risk_acceptance.product %}
				<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Product:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.product.name }}</span></p>
			{% endif %}
			
			{% if long_risk_acceptance.owner %}
				<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Owner:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.owner.username }}</span></p>
			{% endif %}
			
			{% if long_risk_acceptance.accepted_by %}
				<p style="margin: 10px 0;"><strong style="color: #333;">{% blocktranslate %}Accepted By:{% endblocktranslate %}</strong> <span style="color: #666;">{{ long_risk_acceptance.accepted_by.username }}</span></p>
			{% endif %}
			
			{% if long_risk_acceptance.reactivate_expired %}
				<p style="margin: 10px 0; background-color: #d4edda; padding: 10px; border-radius: 3px; border-left: 3px solid #28a745;"><strong style="color: #155724;">{% blocktranslate %}✓ Findings will be reactivated on expiration{% endblocktranslate %}</strong></p>
			{% endif %}

			<div style="background-color: #f0f0f0; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107; margin-top: 15px;">
				<p style="margin: 0; color: #333;"><strong>{% blocktranslate %}Total Affected Findings:{% endblocktranslate %}</strong> <span style="color: #d9534f; font-size: 18px; font-weight: bold;">{{ findings_count|default:"0" }}</span></p>
			</div>

			<div style="background-color: #f0f0f0; padding: 15px; border-radius: 4px; border-left: 3px solid #ffc107; margin-top: 15px;">
				<h4 style="color: #333; margin-top: 0; margin-bottom: 10px;">{% blocktranslate %}Engagements:{% endblocktranslate %}</h4>
				{% if long_risk_acceptance.engagement_set.all %}
					{% for engagement in long_risk_acceptance.engagement_set.all %}
							<br/>
						<p style="margin: 8px 0; padding-left: 10px; border-left: 2px solid #ffc107; color: #555;">
							• <strong>{{ engagement.name }}</strong>
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