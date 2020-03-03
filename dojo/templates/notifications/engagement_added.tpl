{% if type == 'mail' %}
    Hello,

    The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}". It can be viewed here: {{ url }}

    Kind regards,
    {{ system_settings.team_name }}
{% elif type == 'alert' %}
    The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}".
{% elif type == 'slack' %}
    The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}". It can be viewed here: {{ url }}
{% endif %}