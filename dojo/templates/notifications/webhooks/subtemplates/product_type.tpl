{% load display_tags %}
{% url 'view_product_type' product_type.id as product_type_url_ui %}
{% url 'product_type-detail' product_type.id as product_type_url_api %}
product_type:
    name: {{ product_type.name | default_if_none:'' | tojson(0) }}
    id: {{ product_type.pk }}
    url_ui: {{ product_type_url_ui | full_url | tojson(0) }}
    url_api: {{ product_type_url_api | full_url | tojson(0) }}
