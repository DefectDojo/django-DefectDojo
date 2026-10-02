---
title: Threat Intelligence
description: Exploit- und Bedrohungsnachweise als vollwertiger Eingabewert für Priorität
  und Risiko
weight: 2
audience: pro
---

DefectDojo Pro reichert Ihre Befunde mit **dedizierter Threat Intelligence** an – Exploit-Verfügbarkeit, bekannte Ausnutzung und Aktivitäten von Bedrohungsakteuren – und bezieht dies in Priorität und Risiko ein. Dies geht weit über EPSS und das CISA-KEV-Flag hinaus.

## Was Sie erhalten

Jeder Befund mit einer CVE wird nächtlich mit einem kuratierten Intelligence-Feed abgeglichen, der aus CISA KEV, Metasploit, Exploit-DB, Nuclei-Templates und der Verfolgung öffentlicher Proof-of-Concepts aufgebaut ist. Liegen Exploit-Nachweise vor, zeigt der Befund eine **Threat-Intelligence**-Karte:

* ein **Exploit-Reifegrad**-Badge – *Keiner → PoC → Weaponized → Aktiv ausgenutzt*
* ein **Threat Score** (0–100)
* **Nachweis-Chips, die auf den jeweiligen Beleg verlinken** – der KEV-Eintrag (mit Aufnahmedatum), Einsatz in Ransomware, ein Metasploit-Modul, ein Exploit-DB-Eintrag, ein Nuclei-Template sowie öffentliche Proof-of-Concept-Repositories
* eine leicht verständliche Zeile, die erklärt, **warum** die Priorität des Befunds gestiegen ist

Über die Karte hinaus ist diese Intelligence in der gesamten Anwendung nutzbar:

* eine **Spalte „Exploit-Reifegrad"** in der Befundliste – sortier- und filterbar (zum Beispiel „Nur Weaponized oder Aktiv")
* eine Kachel **„Dringend & aktiv ausgenutzt"** im Priority-Layout-Dashboard, die aktive Befunde mit Risiko „Dringend" zählt, die in freier Wildbahn ausgenutzt werden – ein Klick öffnet die entsprechend gefilterte Befundliste
* ein **Benachrichtigungsereignis** (`threat_intel_alert`), wenn die CVE eines bestehenden Befunds neue Exploit-Nachweise erhält, etwa durch Aufnahme in CISA KEV oder ein neues Metasploit-Modul. Nur Höherstufungen – wenn Nachweise stillschweigend veralten, erfolgt keine Benachrichtigung.

## Wie sich dies auf die Bewertung auswirkt

Die Priority-Engine kombinierte bisher bereits Schweregrad, Geschäftskontext und einen „externen Score", der aus EPSS + KEV gebildet wird. Threat Intelligence verallgemeinert diesen externen Score: Jede Art von Exploit-Nachweis wirkt als Untergrenze auf der EPSS-Skala.

| Evidence | Priority floor (EPSS-equivalent) |
|---|---|
| Active exploitation + ransomware/named actor | 45% |
| In CISA KEV **and** used in ransomware | 30% |
| In KEV or exploited in the wild | 20% |
| Weaponized public exploit (Metasploit / Exploit-DB) | 15% |
| Nuclei detection template exists | 12% |
| Public proof-of-concept only | 8% |
| No exploit evidence | no change |

Der externe Score eines Befunds ist der **höhere** Wert aus seinem EPSS-abgeleiteten Wert und der höchsten der oben genannten Untergrenzen – Threat Intelligence kann einen Score also nur *anheben*, niemals senken, und ein Befund, dessen EPSS-Wert die Untergrenze bereits übersteigt, bleibt unverändert. Der vertraute, produkttypbezogene **Skalierungsfaktor für den externen Score** in Ihren Prioritization-Engine-Einstellungen skaliert diesen Beitrag genau wie bisher bei EPSS/KEV.

### Die Risikountergrenze für aktiv ausgenutzte Schwachstellen

Die obige Tabelle erhöht die **Priorität**, jedoch proportional zum Basis-Schweregrad eines Befunds. Das hat eine Konsequenz, die man klar benennen sollte: Ein Befund mit Schweregrad Niedrig, dessen CVE in freier Wildbahn ausgenutzt wird, erhält nur einen kleinen absoluten Anstieg und könnte dennoch in einer niedrigen **Risiko**-Kategorie verbleiben. Die meisten Teams halten das für falsch – „aktiv ausgenutzt" sollte niemals unter Niedrig einsortiert werden.

Deshalb gibt es eine zweite, kategorische Regel. Meldet Threat Intelligence eine **aktive Ausnutzung in freier Wildbahn**, wird die Priorität des Befunds mindestens auf das Niveau einer konfigurierten Risiko-Kategorie angehoben – unabhängig davon, was die gewichtete Berechnung allein ergeben hätte. Standardmäßig ist dies auf **Handlungsbedarf** gesetzt; jeder Produkttyp kann diese Untergrenze in den Prioritization-Engine-Einstellungen unter *Risikountergrenze für aktiv ausgenutzte Schwachstellen* auf Dringend anheben, absenken oder deaktivieren.

Die Untergrenze wirkt ausschließlich nach oben – sie stuft einen Befund nie herab, und ein Befund, der von sich aus bereits höher bewertet ist, bleibt unangetastet. Da sie auf die Priorität wirkt, ergeben sich Risiko-Kategorie und Risiko-Score automatisch daraus, sodass jede Liste, jeder Filter, jedes Diagramm und jede SLA-Berechnung dieselbe konsistente Zahl sieht.

## Befunde ohne CVE

Threat Intelligence wird über die CVE abgeglichen. Viele Befunde – die meisten SAST-Ergebnisse, Secrets, Fehlkonfigurationen, benutzerdefinierte Regeln – haben keine CVE, und für sie existiert nirgendwo eine Threat Intelligence auf Ebene der einzelnen Schwachstelleninstanz (das gilt für jeden Anbieter, nicht nur für DefectDojo). Diese Befunde:

* behalten ihre **exakte** aktuelle Priorität und ihr Risiko – die Funktion senkt niemals einen Score
* werden weiterhin anhand aller übrigen Engine-Eingaben priorisiert (Schweregrad, Geschäftskritikalität, Exposition und so weiter)
* zeigen auf der Karte „Keine Threat Intelligence verfügbar – dieser Befund hat keine CVE, gegen die abgeglichen werden kann" an, im Unterschied zu einem CVE-Befund, für den bislang schlicht kein bekannter Exploit vorliegt

Eine ehrliche Konsequenz daraus: In einer gemischten Warteschlange sinken Befunde ohne CVE im *relativen* Rang, sobald Befunde mit CVE Exploit-Nachweise erhalten – auch wenn sich ihr eigener Score nicht ändert.

## Vertrauenswürdigkeit und Stabilität der Bewertung

* **Signierte Intelligence.** Jedes nächtliche Bundle wird von DefectDojo kryptografisch signiert; Ihre Instanz lehnt manipulierte oder unsignierte Daten ab. Air-Gapped-Instanzen importieren dasselbe signierte Bundle mit einem Offline-Verifizierungsschritt.
* **Kein Score-Flackern.** Höherstufungen durch neue Nachweise gelten ab der Nacht, in der sie erscheinen. Fällt ein Nachweis bei einer Quelle *weg*, bleiben die Scores für ein Stabilitätsfenster (standardmäßig 14 Tage) unverändert – ein kurzzeitiger Ausfall eines Feeds bringt Ihre Warteschlange nie ins Wanken, und echte Rückstufungen setzen sich nach diesem Fenster ruhig durch.
* **Air-Gapped-Unterstützung.** Das tägliche Bundle (einschließlich EPSS-Daten) kann übertragen und offline importiert werden, sodass isolierte Instanzen dieselbe Anreicherung erhalten.

## Self-Hosted-Bereitstellungen

DefectDojo-Cloud-Instanzen benötigen keine Konfiguration. Bei Self-Hosted-Instanzen stehen drei Optionen zur Verfügung:

* **Verbunden (Standard).** Die Instanz ruft das signierte Bundle nächtlich per HTTPS von `intel.defectdojo.com` ab. Dieses Ziel wird von keiner anderen DefectDojo-Funktion verwendet und muss daher meist explizit freigegeben werden: Öffnen Sie ausgehenden Verkehr auf Port 443 zu diesem Host, und fügen Sie ihn unter Kubernetes Ihrer Egress-Netzwerkrichtlinie hinzu. Beachten Sie, dass der Abruf auf dem **Celery-Worker** erfolgt, nicht auf dem Web-Pod – Proxy-Einstellungen müssen also auch diese Arbeitslast erreichen.
* **Interner Mirror.** Verweisen Sie mit `DD_THREAT_INTEL_BUNDLE_URL` (sowie den zugehörigen Digest- und Signatur-URLs) auf einen Speicherort in Ihrem Netzwerk, den Sie selbst synchronisieren. Die Signaturprüfung gilt weiterhin, sodass ein Mirror die Daten nicht verändern kann.
* **Air-Gapped.** Übertragen Sie das Bundle und seine Signatur manuell und importieren Sie sie mit `manage.py load_threat_intel_bundle --file <bundle>`. Die Signatur wird beim Import verifiziert.

Kann die Instanz den Feed nicht erreichen, schlägt die Funktion sicher fehl (fail closed): Der Lauf wird als fehlgeschlagen protokolliert, und Ihre bestehenden Scores und Nachweise bleiben exakt unverändert. Nichts verschlechtert sich außer der Aktualität der Intelligence.

## Aktivierung

Die Funktion ist standardmäßig deaktiviert. Administratoren können sie direkt aktivieren oder zunächst im **Shadow-Modus** ausführen – dabei werden die potenziellen Scores berechnet, ohne live etwas zu ändern, und ein Drift-Bericht zeigt genau, welche Befunde sich verschieben würden – bevor sie eingeschaltet wird. Wenden Sie sich an den Support, oder lesen Sie das Betriebs-Runbook für die empfohlene Einführung auf großen Instanzen.
