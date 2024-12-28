{% load i18n %}
{% load static %}
{% load navigation_tags %}
{% load display_tags %}

<!DOCTYPE html>
<html>
    <body>
    </body>

<html lang="pl">
	<head>
		<meta charset="UTF-8" />
		<meta name="viewport" content="width=device-width, initial-scale=1.0" />
		<meta http-equiv="X-UA-Compatible" content="ie=edge" />
		<title>Devsecops</title>
		
		<style>
            {% block styles_email %}
			.proton-body {
				display: block;
				padding: 0px;
				margin: 0px;
			}

			.body-margin{
				padding-top: 100px;
				padding-left: 20px;
				padding-right: 20px;
				font-style: Arial;
			}

			.king-regards{
				padding-top: 100px;
				padding-left: 20px;
				padding-right: 20px;
				font-style: italic;
			}

			.proton-wrapper {
				width: 100%;
				display: block;
				overflow: hidden;
				box-sizing: border-box;
				color: #000000;
				background: #ffffff;
				font-size: 18px;
				font-weight: normal;
				font-family: 'Baloo 2', 'Open Sans', 'Roboto', 'Segoe UI', 'Helvetica Neue', Helvetica, Tahoma, Arial, monospace, sans-serif;
			}

			.proton-table {
				border-collapse: collapse;
				border-spacing: 0;
				border: 0px;
				width: 640px;
				max-width: 90%;
				margin: 100px auto;
				border-radius: 10px;
				overflow: hidden;
                padding: 0px;
				box-shadow: 3px 3px 10px rgba(0, 0, 0, 0.5);
			}

			.proton-table tr {
				background: #ffffff;
			}

			.proton-table td,
			.proton-table th {
				border: 0px;
				border-spacing: 0;
				border-collapse: collapse;
			}

			.proton-table tr td {
				padding: 0px 40px;
				box-sizing: border-box;
				padding: 0px;
			}

			.proton-margin-header {
                float: left;
                width: 100%;
                overflow: hidden;
                height: 70px;
                background-color: #000508;
                padding-bottom: 0px;
                box-sizing: border-box;
				border-bottom: 8px solid #06a2b7;
				display:flex
            }
			.proton-margin-bottom {
                float: left;
                width: 100%;
                overflow: hidden;
                height: 70px;
                background-color: #000508;
                padding-bottom: 0px;
                box-sizing: border-box;
            }

			.proton-div {
				float: left;
				width: 100%;
				overflow: hidden;
				box-sizing: border-box;
			}

			.proton-table h1,
			.proton-table h2,
			.proton-table h3,
			.proton-table h4 {
				float: left;
				width: 100%;
				margin: 0px 0px 20px 0px !important;
				padding: 0px;
			}

			.proton-table h1 {
                font-size: 33px;
                color: #ebf1ff;
                padding: 20px;
            }

			.proton-table h2 {
				font-size: 26px;
			}

			.proton-table h3 {
				font-size: 23px;
			}

			.proton-table p {
				width: 100%;
				font-size: 18px;
				margin: 0px 0px 10px 0px !important;
			}

			.proton-table h4 {
				font-size: 20px;
			}

			.proton-table a {
				color: #097887;
				font-weight: bold;
			}

			.proton-table a.proton-link {
				display: inline-block;
				width: auto !important;
				outline: none !important;
				text-decoration: none !important;
			}

			.proton-table,
			.proton-table a {
				display: block;
				max-width: 100%;
				margin-bottom: 0px;
				border: 0px;
				border-radius: 10px;
			}

			.proton-table a.proton-button {
				display: inline-block;
				font-weight: bold;
				font-size: 17px;
				padding: 15px 40px;
				margin: 20px 0px;
				color: #040404 !important;
				background: #16cdfb !important;
				border-radius: 10px;
				text-decoration: none;
				outline: none;
			}

			.proton-button-actions-reject{
				font-size: 12px;
				padding: 2px 0px;
				margin: 20px 2px;
				color: #040404 !important;
				background: #ff7902  !important;
				border-radius: 10px;
				text-decoration: none;
				outline: none;
				width: 60px;
				float: left;
		}

		.proton-button-actions-accept{
				font-size: 12px;
				padding: 2px 0px;
				margin: 20px 2px;
				color: #040404 !important;
				background: #00ab46 !important;
				border-radius: 10px;
				text-decoration: none;
				outline: none;
				width: 60px;
				float: left;
		}

			.proton-flex {
				float: left;
				width: 100%;
				text-align: center;
			}

			.proton-divider {
				float: left;
				width: 100%;
				overflow: hidden;
				margin: 20px 0px;
				border-top: 2px solid #f2f2fd;
			}

			.proton-flex {
				margin: 10px;
				max-width: 15%;
				width: 40px;
			}
        {% endblock styles_email %}
		</style>
	</head>
	<body class="proton-body">
		<div class="proton-wrapper">
			<table class="proton-table">
				<tbody>
					<tr class="proton-tr">
						<td class="proton-td" colspan="10" style="">
							<div class="proton-margin-header">
								<div class="cls-img">
									{% if system_settings.team_name %}
									<h1>{{ system_settings.team_name }}</h1>
									{% else %}
										<h1>Defect Dojo</h1>
									{% endif %}
								</div>
							</div>
							<div class="body-margin">
								<h2>{% trans "Hello, " %}{{ user.first_name }}</h2>
								{%block description %}
									{%if owner %}
										<b>{{ owner }}</b> {{ description|safe }}
									{% else %}
										{{ description|safe }}
									{% endif %}
								{% endblock%}
								<p>
									{% block content %}

										{%block contect_description%}
										{% endblock %}

										{% block risk%}
										{% endblock%}

										{% block event %}
											More information on this event can be found here:
											<br/>
											{% blocktranslate trimmed with event_url=url|full_url team_name=system_settings.team_name %}
												<center><a href="{{event_url}}" class="proton-button" target="_blank">Go {{team_name}}</a></center>
											{% endblocktranslate %}
										{% endblock%}
									{% endblock %}
								</p>
							</div>
						</td>
					</tr>
					<tr class="proton-tr">
						<td class="proton-td" colspan="10" style="">
							<div class="king-regards">
								<b>{% trans "Kind regards" %},</b>
								<br/>
								{% if system_settings.team_name %}
									{{ system_settings.team_name }}
								{% else %}
									Defect Dojo
								{% endif %}
								<br/><br/>
							</div>
						</td>
					</tr>
					<tr class="proton-tr">
						<td class="proton-td" colspan="10" style="">
							<div class="proton-divider"></div>
							<center>
								<span style="color: #000000"> © 2024 DevSecOps Team</span>
							</center>
							<div class="proton-margin-bottom"></div>
						</td>
					</tr>
				</tbody>
			</table>
		</div>
	</body>
	</html>