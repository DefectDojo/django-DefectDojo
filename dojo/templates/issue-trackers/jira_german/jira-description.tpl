{% load navigation_tags %}
{% load display_tags %}
{% load get_endpoint_status %}
{% url 'view_product' finding.test.engagement.product.id as product_url %}
{% url 'view_engagement' finding.test.engagement.id as engagement_url %}
{% url 'view_finding' finding.id as finding_url %}

Nach dem [Schwachstellenmanagementprozess| https://wiki.teambank.de/confluence/spaces/IB/pages/521544189/ITG.111_Schwachstellenmanagement+ausf%C3%BChren] wird ein Ticket eröffnet, wenn die Schwachstellen einer Applikation oder eines Assets die in der [Patchmanagementrichtlinie|https://ohb.easycredit.intern/#default/item/c.policy.TeamBank_P.u_v4ASyfEfAXmwBQVo2gcw.-1/~AahbIml0ZW1Eb2N1bWVudGF0aW9uIl0~] definierten Behebungszeiten überschreitet.
Der [Application Manager|https://ohb.easycredit.intern/#default/item/c.role.TeamBank_P.ErtXQOrkEedWBwBQVoVVJw.-1/~AfBbImNvbXBvbmVudF9jb21tZW50U3RyZWFtMTk5Il0~] der betroffenen Applikation ist für die Behebung der Schwachstellen verantwortlich.
Die Bearbeitungszeiten hierfür regelt die [Schwachstellenmanagementrichtlinie|https://ohb.easycredit.intern/#default/item/c.policy.TeamBank_P.t_GTUSyfEfAXmwBQVo2gcw.-1/~AahbIml0ZW1Eb2N1bWVudGF0aW9uIl0~].
Nach Überschreitung dieser Zeit wird der Vorgang an die CISO-Organisation eskaliert und eine Risikobehandlung durchgeführt.

Die folgende Schwachstelle von {{ finding.test.engagement.product.name }} überschreitet den Schwellwert für die Behebungszeit:

---

*Schwachstellentitel:*  
{{ finding.title|jiraencode }}

{% if finding.endpoints.all %}
*Betroffenes System / Endpoint:*  
{% for endpoint in finding|get_vulnerable_endpoints %}
- {{ endpoint }}
{% endfor %}
{% else %}
*Betroffenes Asset:*  
{{ finding.test.engagement.product.name }}
{% endif %}

*DefectDojo-Link:*  
{{ finding_url|full_url }}

*Schweregrad / Severity:*  
{{ finding.severity }}

{% if finding.cve %}
*CVE:*  
{{ finding.cve }}
{% else %}
*CVE:*  
Nicht bekannt
{% endif %}

{% if finding.cvssv3_score %}
*CVSS v3:*  
{{ finding.cvssv3_score }}{% if finding.cvssv3 %} ({{ finding.cvssv3 }}){% endif %}
{% endif %}

*Festgestellt durch:*  
{{ finding.test.engagement.name }}

---

*Beschreibung der Schwachstelle:*  
{{ finding.description|safe }}
