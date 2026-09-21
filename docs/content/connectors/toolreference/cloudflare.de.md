---
title: "Cloudflare"
description: "Einrichtung des Cloudflare Upstream-Connectors für DefectDojo"
weight: 36
audience: pro
---
Der Cloudflare-Connector importiert **Security-Center-Insights** — Probleme mit der Sicherheitslage, die Cloudflare zu Ihrem Konto und Ihren Zonen aufzeigt, etwa einen fehlenden DMARC-Eintrag, nicht aktiviertes DNSSEC oder ein Zertifikatsproblem. DefectDojo erstellt für jede Zone (Domain) mit offenen Insights einen Eintrag, plus einen Eintrag auf Kontoebene für Insights, die keiner bestimmten Zone zugeordnet sind.

#### Voraussetzungen

Sie benötigen ein Cloudflare-**API-Token** (nicht den veralteten Global API Key). Erstellen Sie eines im Cloudflare-Dashboard unter **My Profile > API Tokens > Create Token**. Die schnellste Option ist die Vorlage **„Read all resources"**; für ein Token mit minimalen Rechten gewähren Sie **Zone > Zone > Read** (alle Zonen) sowie kontoweiten Lesezugriff für Security Center.

#### Connector-Zuordnungen

1. Geben Sie `https://api.cloudflare.com/client/v4` in das Feld **Location** ein.
2. Geben Sie das API-Token in das Feld **Secret** ein.
3. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

DefectDojo ermittelt automatisch die Konten und Zonen, auf die das Token zugreifen kann — es ist keine Konto-ID erforderlich. Es werden nur offene (aktive, nicht verworfene) Insights importiert, sodass Insights, die Sie in Cloudflare beheben oder verwerfen, beim nächsten Sync automatisch in DefectDojo als behoben markiert werden.
