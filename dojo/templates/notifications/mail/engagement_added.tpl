{% load navigation_tags %}
{% load display_tags %}
{% url 'view_product' engagement.product.id as product_url %}
{% url 'view_engagement' engagement.id as engagement_url %}
<html>
    <body>
        {% autoescape on %}
            <p>
                Hello,
            </p>
            <p>
                The engagement "{{ engagement.name }}" has been created in the product "{{ engagement.product }}". It can be viewed here: <a href="{{product_url|full_url}}">{{product}}</a> / <a href="{{engagement_url|full_url}}">{{ engagement.name }}</a>
            </p>
            <br/>
            <br/>
                Kind regards,<br/>
            <br/>
                {% if system_settings.team_name %}
                    {{ system_settings.team_name }}
                {% else %}
                    Defect Dojo
                {% endif %}
            <br/>
            <br/>
            <p>
                {% url 'notifications' as notification_url %}
                You can manage your notification settings here: <a href="{{ notification_url|full_url }}">{{ notification_url|full_url }}</a>
            </p>
            {% if system_settings.disclaimer and system_settings.disclaimer.strip %}
                <br/>
                <div style="background-color:#DADCE2; border:1px #003333; padding:.8em; ">
                    <span style="font-size:16pt;  font-family: 'Cambria','times new roman','garamond',serif; color:#ff0000;">Disclaimer</span><br/>
                    <p style="font-size:11pt; line-height:10pt; font-family: 'Cambria','times roman',serif;">{{ system_settings.disclaimer }}</p>
                </div>
            {% endif %}
        {% endautoescape %}
    </body>
</html>
