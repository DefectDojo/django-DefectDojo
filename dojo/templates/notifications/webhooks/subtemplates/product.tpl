{% load display_tags %}
{% if product_type %}
{% include 'notifications/webhooks/subtemplates/product_type.tpl' with product_type=product_type %}
{% else %}
{% include 'notifications/webhooks/subtemplates/product_type.tpl' with product_type=product.prod_type %}
{% endif %}
{% url 'view_product' product.id as product_url_ui %}
{% url 'product-detail' product.id as product_url_api %}
product:
    name: {{ product.name | default_if_none:'' }}
    id: {{ product.pk }}
    url_ui: {{ product_url_ui|full_url }}
    url_api: {{ product_url_api|full_url }}
