{% load i18n %}
{% autoescape off %}
{% blocktranslate %}You're receiving this email because you requested a password reset for your user account at {{ site_name }}.{% endblocktranslate %}

{% translate "Please go to the following page and choose a new password:" %}
{% block reset_link %}{{ protocol }}://{{ domain }}{% url 'password_reset_confirm' uidb64=uid token=token %}{% endblock %}
{% blocktranslate %}The link above expires on: {{ link_expiration_date }}{% endblocktranslate %}


{% translate "Thanks for using our site!" %}
{% blocktranslate %}The {{ site_name }} team{% endblocktranslate %}
{% endautoescape %}