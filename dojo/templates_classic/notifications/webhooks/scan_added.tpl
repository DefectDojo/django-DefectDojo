{% include 'notifications/webhooks/subtemplates/base.tpl' %}
{% include 'notifications/webhooks/subtemplates/test.tpl' %}
finding_count: {{ finding_count }}
findings:
  new: 
{% include 'notifications/webhooks/subtemplates/findings_list.tpl' with findings=findings_new %}
  reactivated: 
{% include 'notifications/webhooks/subtemplates/findings_list.tpl' with findings=findings_reactivated %}
  mitigated: 
{% include 'notifications/webhooks/subtemplates/findings_list.tpl' with findings=findings_mitigated %}
  untouched: 
{% include 'notifications/webhooks/subtemplates/findings_list.tpl' with findings=findings_untouched %}
