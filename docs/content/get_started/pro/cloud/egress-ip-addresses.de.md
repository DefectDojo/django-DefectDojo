---
title: Ausgehende IP-Adressen (Egress)
description: Die ausgehenden IP-Adressen, von denen aus sich DefectDojo Cloud verbindet,
  zur Freigabe in Ihren externen Firewalls.
weight: 5
audience: pro
---

Wenn DefectDojo Cloud Kontakt zu Ihren Systemen aufnimmt — Connectors, die die API eines Scanners
synchronisieren, Issues an Jira oder ServiceNow übertragen, Benachrichtigungs-Webhooks senden oder
E-Mails per SMTP zustellen — werden diese Verbindungen **ausgehend initiiert**, aus
Ihrer DefectDojo-Umgebung heraus. Wenn sich das System auf der anderen Seite hinter einer
Firewall befindet, müssen Sie die ausgehenden (Egress-)IP-Adressen von DefectDojo zulassen, damit
diese Verbindungen nicht blockiert werden.

Diese Seite zeigt, wo Sie diese Egress-IP-Adressen finden.

## Egress vs. Ingress

Dies sind zwei unterschiedliche Dinge, und diese Seite behandelt nur das erste:

- **Egress (diese Seite)** — die Quell-IP-Adressen, von denen aus sich DefectDojo Cloud
  verbindet, wenn es **nach außen** zu *Ihren* externen Systemen reicht. Geben Sie diese in
  **Ihren** Firewalls frei, damit DefectDojo die Systeme erreichen kann, mit denen es integriert ist.
- **Ingress** — die Regeln, die steuern, wer **Ihre** DefectDojo-Instanz erreichen darf.
  Diese werden als Firewall-Regeln im Cloud Manager verwaltet, nicht hier.
  Siehe [Fehlerbehebung bei der Konnektivität](../connectivity-troubleshooting/) und den
  Schritt zu den Firewall-Regeln unter
  [Eine zusätzliche Cloud-Instanz einrichten](../additional-cloud-instance/).

## Mandantenfähige Bereitstellungen (Multi-Tenant)

Standard-, Pay-as-you-go- und Premium-Instanzen laufen auf gemeinsam genutzten, regionalen
Google Kubernetes Engine (GKE)-Clustern. Ausgehende Verbindungen stammen von den
externen IP-Adressen der Nodes in der Region, in der Ihre Instanz läuft.

Die aktuelle Liste der Node-Egress-IPs wird als JSON-Feed veröffentlicht, gruppiert nach
Region:

<https://storage.googleapis.com/defectdojo-node-ips/node_ips.json>

Der Feed sieht folgendermaßen aus:

```json
{
  "description": "External IPs for DefectDojo Cloud GKE nodes, grouped by region",
  "generated_at": "2026-08-06T20:17:26.372476+00:00",
  "regions": {
    "us-east4": [
      "34.21.115.236/32",
      "34.48.120.182/32"
    ],
    "europe-west3": [
      "34.40.61.46/32",
      "34.89.189.26/32"
    ]
  }
}
```

So geben Sie den Egress-Traffic von DefectDojo frei:

1. Ermitteln Sie die Region, in der Ihre Instanz läuft (der Serverstandort, den Sie
   bei der Bereitstellung der Instanz ausgewählt haben).
2. Lassen Sie jede unter dieser Region aufgeführte IP-Adresse zu. Jeder Eintrag ist ein
   `/32`-CIDR (Einzelhost).

**Diese Liste ändert sich im Laufe der Zeit.** Nodes werden hinzugefügt und ersetzt, während die Plattform
automatisch skaliert, sodass die Menge der Egress-IPs für eine Region nicht fest ist. Behandeln Sie den JSON-
Feed als maßgebliche Quelle, anstatt die Adressen einmalig zu kopieren:

- Rufen Sie den Feed programmatisch ab und aktualisieren Sie Ihre Firewall-Freigabeliste daraus nach einem
  Zeitplan, oder
- Überprüfen Sie den Feed regelmäßig und gleichen Sie Ihre Regeln entsprechend ab.

Wenn Ihre Firewall keine sich ändernde Liste verfolgen kann und Sie eine kleine, stabile Menge von
Adressen benötigen, sprechen Sie mit Ihrem DefectDojo-Ansprechpartner über eine **Dedicated**-Instanz
(siehe unten).

## Single-Tenant-Bereitstellungen (Dedicated)

Eine Instanz der Stufe **Dedicated** läuft in einem eigenen GCP-Projekt und einer eigenen VPC, und ihre
Egress-IP-Adresse ist **stabil** — sie wird bei der Bereitstellung der Instanz zugewiesen
und ändert sich nicht, wenn die Plattform skaliert.

Da sie an Ihre spezifische Instanz gebunden ist, wird die stabile Egress-IP nicht im öffentlichen Feed
veröffentlicht. Wenden Sie sich an [support@defectdojo.com](mailto:support@defectdojo.com),
um die Ihrer Dedicated-Instanz zugewiesene(n) Egress-IP-Adresse(n) zu erhalten, und
geben Sie diese in Ihren externen Firewalls frei.

*Haben Sie eine Frage, die diese Seite nicht beantwortet? Wenden Sie sich an Ihren DefectDojo-
Ansprechpartner.*
