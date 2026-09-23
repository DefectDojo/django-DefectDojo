---
title: "Sonatype IQ"
description: "Einrichtung des Sonatype IQ Upstream-Connectors für DefectDojo"
weight: 128
audience: pro
---
Der Sonatype-IQ-Connector verwendet die REST-API des Sonatype-IQ-Servers (Nexus Lifecycle), um Open-Source-Komponentenschwachstellen zu importieren. Er zählt jede Anwendung in Ihrer IQ-Organisation auf und importiert für jede die Komponentenschwachstellen aus dem letzten Bericht dieser Anwendung auf der von Ihnen konfigurierten Lifecycle-Stufe. DefectDojo erstellt automatisch für jede Anwendung einen Eintrag — es gibt keine Pro-Anwendungs-Konfiguration.

#### Voraussetzungen

Sie benötigen ein Sonatype-IQ-Benutzerkonto mit der Berechtigung **View IQ Elements** für die zu importierenden Anwendungen. Sonatype empfiehlt die Authentifizierung mit einem **User Token** (generiert unter **My Profile > User Token** im IQ Server) statt eines Passworts; die beiden Teile des Tokens werden unten den Feldern Username und User Token zugeordnet. Der Connector funktioniert sowohl mit selbstgehostetem IQ Server als auch mit von Sonatype gehosteten (SaaS-)Instanzen.

#### Connector-Zuordnungen

1. Geben Sie im Feld **Location** die Basis-URL Ihres IQ-Servers ein — für einen selbstgehosteten Server `https://iq.example.com`; für eine von Sonatype gehostete Instanz `https://<tenant>.sonatype.app/platform`.
2. Geben Sie den IQ-Benutzer (oder den User-Code-Teil Ihres User Tokens) in das Feld **Username** ein.
3. Geben Sie das IQ-User-Token (oder das Passwort) in das Feld **User Token** ein.
4. Legen Sie optional eine **Stage** fest, um zu wählen, dessen Bericht pro Anwendung importiert wird (`build`, `stage-release`, `release` usw.). Leer lassen, um `build` zu verwenden.
5. Legen Sie optional einen **Minimum Severity**-Wert fest, um einzuschränken, welche Befunde importiert werden.

Jede Anwendung wird zu einem Eintrag, und jedes Sicherheitsproblem im letzten Bericht dieser Anwendung für die gewählte Stufe wird als Befund importiert. Der Schweregrad wird aus dem numerischen Score des Issues abgeleitet, und CVE-Referenzen, die CWE, der CVSS-Vektor sowie die Package-URL (PURL) der betroffenen Komponente werden einbezogen, sofern verfügbar.
