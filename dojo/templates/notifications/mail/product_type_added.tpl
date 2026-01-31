{% load i18n %}
{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product_type' product_type.id as product_type_url %}

<html>
  <body>
    {% autoescape on %}
      <p>{% trans "Hello" %},</p>

      <p>
        {% blocktranslate trimmed with title=title prod_url=product_type_url|full_url %}
          The new product type "{{ title }}" has been added.
          It can be viewed here: <a href="{{ prod_url }}">{{ title }}</a>
        {% endblocktranslate %}
      </p>

      <br><br>

      {% trans "Kind regards" %},<br><br>

      {% if system_settings.team_name %}
        {{ system_settings.team_name }}
      {% else %}
        Defect Dojo
      {% endif %}
    {% endautoescape %}
  </body>
</html>
