{% load i18n %}{% blocktranslate trimmed with eng_product=engagement.product test_type=test.test_type %}
New test added for engagement {{ eng_product }}: {{ test_type }}.
{% endblocktranslate %}