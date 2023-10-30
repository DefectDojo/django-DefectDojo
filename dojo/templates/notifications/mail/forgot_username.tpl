{% load i18n %}
{% autoescape off %}
{% blocktranslate %}You're receiving this email because you requested your username for your user account at {{ site_name }}.{% endblocktranslate %}

{% translate 'Here is your username:' %} {{ user.get_username }}


{% translate "Thanks for using our site!" %}
{% blocktranslate %}The {{ site_name }} team{% endblocktranslate %}
{% endautoescape %}