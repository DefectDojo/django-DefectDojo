{% load display_tags %}
{% load as_json %}
{% if user %}
{% url 'view_user' user.id as user_url_ui %}
{% url 'user-detail' user.id as user_url_api %}
user:
    id: {{ user.pk }}
    email: {{ user.email | as_json_no_html_esc }}
    username: {{ user.username | as_json_no_html_esc }}
    first_name: {{ user.first_name | as_json_no_html_esc }}
    last_name: {{ user.last_name | as_json_no_html_esc }}
    url_ui: {{ user_url_ui | full_url | as_json_no_html_esc }}
    url_api: {{ user_url_api | full_url | as_json_no_html_esc }}
{% else %}
user: {{ user | as_json_no_html_esc }}
{% endif %}
