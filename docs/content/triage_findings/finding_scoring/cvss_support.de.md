---
title: CVSS-Versionsunterstützung
description: Welche CVSS-Versionen DefectDojo bei Befunden speichert, anzeigt und
  akzeptiert
weight: 1
---

DefectDojo unterstützt CVSS-Metadaten bei Befunden, einschließlich des CVSS-4.0-Standards.  Diese Seite beschreibt, welche CVSS-Versionen durchgängig gespeichert werden, wo Sie sie eingeben oder einsehen können, und was Sie hinsichtlich der Parser-seitigen Abdeckung erwarten können.

## Was DefectDojo speichert

Befunde können die folgenden CVSS-Daten tragen:

| Version | Vektor gespeichert | Score gespeichert | UI-Vektor-Builder & Rechner |
| --- | --- | --- | --- |
| **CVSS v4.0** | ✅ | ✅ | ✅ (Pro UI) |
| **CVSS v3 (v3.0 / v3.1)** | ✅ | ✅ | ✅ (Pro UI) |
| **CVSS v2** | Implizit über das Feld **Severity** des Befunds gespeichert; es wird kein separates v2-Vektorfeld gespeichert | N/A | N/A |

Jeder Befund verfügt über eigene Felder `cvssv3` / `cvssv3_score` und `cvssv4` / `cvssv4_score` im zugrunde liegenden Modell.  Diese sind sowohl über die API als auch über die UI zugänglich.

## Wo Sie CVSS-Daten manuell eingeben

Sowohl CVSSv3 als auch CVSSv4 können manuell bei einem Befund eingegeben werden:

- **Formular „Befund bearbeiten“** — fügen Sie eine vollständige CVSS-Vektorzeichenfolge in das entsprechende Feld ein.  Beim Speichern parst DefectDojo den Vektor und berechnet den Score automatisch.
- **Vektor-Builder (Pro UI)** — klicken Sie auf die Schaltfläche 🛠️ neben dem CVSSv3- oder CVSSv4-Eintrag im Formular „Befund bearbeiten“, um den Vektor-Builder zu öffnen.  Erstellen Sie den Vektor interaktiv, und klicken Sie dann auf die Rechner-Schaltfläche, um aus dem resultierenden Vektor einen Score zu berechnen.

> CVSSv4-Vektorzeichenfolgen und der Vektor-Builder wurden der Pro UI in v2.50.3 (22. September 2025) hinzugefügt, und die dazugehörige explizite Rechner-Schaltfläche kam in v2.51.1 (14. Oktober 2025) hinzu.

## Anzeigeeinstellungen

Die Befundansicht berücksichtigt zwei Systemeinstellungen, die steuern, ob CVSSv3- und CVSSv4-Daten für Benutzer angezeigt werden:

- **CVSS 3-Anzeige aktivieren** — zeigt CVSSv3-Vektoren und -Scores bei Befunden an.
- **CVSS 4-Anzeige aktivieren** — zeigt CVSSv4-Vektoren und -Scores bei Befunden an.

Beide können unabhängig voneinander unter Systemeinstellungen festgelegt werden.  Wenn beide aktiviert sind, werden beide Versionen bei Befunden, die beide tragen, nebeneinander angezeigt.

## Parser- und Tool-Abdeckung

DefectDojo kann CVSSv4-Daten bei jedem Befund speichern, aber **ob ein bestimmter Parser die CVSSv4-Felder befüllt, hängt vom vorgelagerten Tool ab**:

- Wenn das vorgelagerte Tool CVSSv4-Vektoren oder -Scores in seinem Exportformat ausgibt, ordnet der Parser diese Felder in der Regel zu.
- Wenn das Tool nur CVSSv2- oder CVSSv3-Daten ausgibt, synthetisiert der Parser keinen v4-Vektor — es gibt keine eingebaute Umwandlung von v3 zu v4.
- Manche älteren Parser bilden CVSSv4-Felder unter Umständen noch nicht ab, selbst wenn das vorgelagerte Tool sie ausgibt.  Wenn Sie einen Parser finden, der CVSSv4-Felder eines Tools auslässt, das sie tatsächlich ausgibt, melden Sie bitte ein Issue.

In der Zwischenzeit bieten Ihnen zwei Wege eine vollständige CVSSv4-Abdeckung, unabhängig von der Parser-Unterstützung:

1. **[Generic Findings Import](/supported_tools/parsers/generic_findings_import/)** — akzeptiert die Spalten `CVSSV4` (Vektor) und `CVSSV4_score` in CSV sowie die Schlüssel `cvssv4` / `cvssv4_score` in JSON.
2. **[Universal Parser](/import_data/pro/specialized_import/universal_parser/)** (Pro) — unterstützt CVSSv4-Vektoren als zuordenbares Feld (hinzugefügt in v2.57.0, 7. April 2026).  Verwenden Sie dies, wenn Ihr Tool JSON oder CSV mit benutzerdefinierten Feldnamen ausgibt, die die integrierten Parser nicht zuordnen.

Die manuelle Eingabe im Formular „Befund bearbeiten“ bleibt als universeller Fallback für jedes Tool oder jeden Bericht verfügbar, das bzw. der CVSSv4 nicht automatisch durchreicht.
