{% extends "notifications/mail/base_email.tpl" %}
{% load i18n %}
{% load static %}

{% block content %}

	{%block contect_description%}
	{% endblock %}

	{% block risk%}
	{% endblock %}

	{% block event %}
		<p>
			Please note that the <strong> link will expire in {{expiration_time}} </strong>.
			If you are unable to download the report within that time frame, you will need to generate a new one
		</p>

		<center><a href="{{url}}" class="proton-button" target="_blank">Downlod Report</a></center>
	{% endblock %}


{% endblock %}
