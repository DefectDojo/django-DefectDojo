{% load display_tags %}
{% load as_json %}
{% url 'view_product_type' product_type.id as product_type_url_ui %}
{% url 'product_type-detail' product_type.id as product_type_url_api %}
product_type:
    name: {{ product_type.name | as_json_no_html_esc }}
    id: {{ product_type.pk }}
    url_ui: {{ product_type_url_ui | full_url | as_json_no_html_esc }}
    url_api: {{ product_type_url_api | full_url | as_json_no_html_esc }}
