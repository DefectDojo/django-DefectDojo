---
title: Multi-Faktor-Authentifizierung (MFA)
description: Richten Sie MFA für Ihr eigenes Konto ein, machen Sie es für Ihre gesamte
  Instanz verpflichtend und stellen Sie den Zugriff für einen Benutzer wieder her,
  der sein Gerät verloren hat
audience: pro
weight: 3
---

Die Multi-Faktor-Authentifizierung fügt der Anmeldung einen zweiten Schritt hinzu: Nach Ihrem Passwort fragt DefectDojo nach einem sechsstelligen Code aus einer Authenticator-App. Wir empfehlen dringend, sie für jeden Benutzer verpflichtend zu machen, auf Instanzen, die nicht hinter SSO liegen.

Die MFA von DefectDojo Pro verwendet eine **TOTP-Authenticator-App** — Google Authenticator, 1Password, Authy oder jede andere App, die einen Standard-QR-Code scannen kann. Es gibt keine E-Mail- oder SMS-Option.

## MFA für Ihr Konto einrichten

1. Gehen Sie zu **Connect \> Authorization \> MFA Settings**.
2. Klicken Sie unter **Personal Multi-Factor Authentication Settings** auf **Set Up MFA**.
3. Scannen Sie den QR-Code mit Ihrer Authenticator-App. Falls Sie ihn nicht scannen können, zeigt der Einrichtungsbildschirm den Schlüssel auch als Text an, den Sie von Hand in Ihre App eingeben können.
4. Geben Sie den sechsstelligen Code ein, den Ihre App anzeigt, und klicken Sie auf **Verify & enable**.
5. DefectDojo zeigt Ihre **Recovery-Codes** an. Speichern Sie sie an einem sicheren Ort, bevor Sie fortfahren — siehe unten. Klicken Sie auf **Copy codes**, bewahren Sie sie auf und klicken Sie dann auf **I've saved them. Continue**.

MFA ist ab diesem Zeitpunkt aktiv. Bei Ihrer nächsten Anmeldung fragt DefectDojo nach Ihrem Passwort zusätzlich nach einem Code.

### Recovery-Codes

Beim Aktivieren von MFA erhalten Sie **zehn Einweg-Recovery-Codes**. Jeder kann einmal anstelle eines Codes aus Ihrer Authenticator-App verwendet werden und wird bei Gebrauch verbraucht.

Sie werden **einmalig** auf dem abschließenden Einrichtungsbildschirm angezeigt. Die Seite „MFA Settings" zeigt danach nur noch an, wie viele Ihnen noch verbleiben, nicht die Codes selbst.

Falls Sie Ihre Recovery-Codes verlieren — oder nach der Verwendung mehrerer einen neuen Satz möchten — klicken Sie auf der Seite „MFA Settings" auf **Regenerate Recovery Codes**. Dies **ersetzt alle Ihre bestehenden Codes**: Zuvor gespeicherte Codes funktionieren danach sofort nicht mehr, speichern Sie den neuen Satz also umgehend.

Recovery-Codes sind es, die Ihnen den Zugang ermöglichen, wenn Sie Ihr Telefon verlieren; bewahren Sie sie daher getrennt von dem Gerät auf, auf dem Ihre Authenticator-App läuft.

### MFA deaktivieren

**Disable MFA** auf der Seite „MFA Settings" deaktiviert MFA für Ihr eigenes Konto. Sie müssen dafür nur angemeldet sein — ein Code zur Bestätigung wird nicht verlangt.

Hat Ihr Administrator MFA verpflichtend gemacht, werden Sie bei Ihrer nächsten Anmeldung erneut zur Einrichtung aufgefordert.

## Anmelden mit MFA

Nach der Eingabe von Benutzername und Passwort fragt DefectDojo nach Ihrem sechsstelligen Code. Falls Sie Ihre Authenticator-App nicht zur Hand haben, geben Sie stattdessen einen Ihrer **Recovery-Codes** in dasselbe Feld ein — dieser Code wird dann verbraucht.

## MFA für alle verpflichtend machen

Superuser können MFA instanzweit verpflichtend machen:

1. Gehen Sie zu **Connect \> Authorization \> MFA Settings**.
2. Aktivieren Sie in der Karte **MFA Settings** — nur für Superuser sichtbar — das Kontrollkästchen **Require Multi-Factor Authentication Globally**.
3. Absenden.

Dies ist **standardmäßig deaktiviert**.

Sobald es aktiviert ist, wird jeder Benutzer, der sich noch nicht registriert hat, bei der nächsten Anmeldung zum MFA-Einrichtungsbildschirm geleitet und **kann diesen nicht überspringen**. Er schließt die Registrierung ab, speichert seine Recovery-Codes und gelangt dann dorthin, wohin er ursprünglich wollte.

### SSO-Benutzer

MFA wird von DefectDojo durchgesetzt und nicht an Ihren Identitätsanbieter delegiert. Ist globales MFA verpflichtend, werden auch Benutzer, die sich über SSO anmelden, zur MFA-Einrichtung geleitet, nachdem ihr Anbieter sie zu DefectDojo zurückgeführt hat, und bei nachfolgenden Anmeldungen nach einem Code gefragt.

Es gibt keine Einstellung, um SSO-Benutzer davon auszunehmen. Erzwingt Ihr Identitätsanbieter bereits eine eigene MFA, entscheiden Sie bewusst, ob Sie beides möchten — das Aktivieren von globalem MFA bedeutet für SSO-Benutzer zwei Abfragen.

## Wiederherstellen eines Benutzers, der sein MFA-Gerät verloren hat

Gehen Sie diese Schritte der Reihe nach durch:

1. **Einen Recovery-Code verwenden.** Hat der Benutzer noch seine Recovery-Codes, gibt er bei der Anmeldung einen davon anstelle eines App-Codes ein und richtet MFA anschließend von Grund auf neu ein.
2. **Ist er noch irgendwo angemeldet,** kann er zu **MFA Settings** gehen und auf **Disable MFA** klicken, ohne dass ein Code nötig ist, und sich danach erneut registrieren.
3. **Einen Administrator bitten, seine MFA zurückzusetzen.** Mit Serverzugriff kann ein Administrator MFA von einem Konto entfernen:

   ```
   python manage.py remove_mfa --username <username>
   ```

   Der Befehl akzeptiert anstelle von `--username` auch `--user-id` oder `--email` (genau eines ist erforderlich; bei `--email` wird Groß-/Kleinschreibung ignoriert). Vor der Änderung wird eine Bestätigung verlangt. Der Benutzer kann sich danach mit nur seinem Passwort anmelden und sich erneut registrieren.

   Dies ist ein Shell-Befehl und benötigt daher Zugriff auf den DefectDojo-Container oder -Host. Es gibt keine entsprechende Schaltfläche in der Benutzeroberfläche oder einen Endpunkt in der API. Wenden Sie sich bei **DefectDojo Cloud** an den [DefectDojo Support](mailto:support@defectdojo.com), um dies ausführen zu lassen.

Das Anlegen eines Ersatzkontos ist **nicht** notwendig — das Zurücksetzen der MFA erhält die bestehenden Berechtigungen, den Verlauf und die Zuweisungen des Benutzers.

## MFA und die API

Ist bei einem Benutzer MFA aktiviert, müssen Anfragen an `/api/v2/api-token-auth/` — den Endpunkt, der Benutzername und Passwort gegen ein API-Token tauscht — zusätzlich zu den Zugangsdaten einen MFA-Code im Feld `mfa_code` enthalten. Akzeptiert wird entweder ein aktueller TOTP-Code oder ein unbenutzter Recovery-Code; die Übergabe eines Recovery-Codes hier **verbraucht** ihn.

Ein fehlender oder falscher Code liefert denselben allgemeinen Fehler *„Unable to log in with provided credentials"* wie ein falsches Passwort. Wenn Token-Anfragen also fehlschlagen, nachdem ein Benutzer MFA aktiviert hat, ist dies als Erstes zu prüfen.

**Bestehende API-Token funktionieren weiterhin.** Das Aktivieren oder Deaktivieren von MFA widerruft oder erneuert bereits ausgestellte Token nicht — die MFA-Prüfung erfolgt bei der Ausstellung eines Tokens, nicht bei jeder damit gestellten Anfrage. Langlebige Automatisierungen, die bereits ein Token besitzen, sind von der MFA-Registrierung eines Benutzers nicht betroffen.
