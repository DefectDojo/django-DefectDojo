---
title: SCIM-Provisionierung
description: DefectDojo Pro-Benutzer über Ihren Identity Provider bereitstellen und
  deaktivieren
weight: 19
audience: pro
---

DefectDojo Pro unterstützt SCIM 2.0, wodurch Ihr Identity Provider DefectDojo-Benutzer direkt erstellen, aktualisieren und deaktivieren kann. Ohne SCIM erfährt DefectDojo erst dann von einem Benutzer, wenn sich dieser anmeldet. Entfernen Sie jemanden aus Ihrem Identity Provider, werden also künftige Anmeldungen verhindert, das DefectDojo-Konto bleibt jedoch aktiv.

SCIM ist von Single Sign-On getrennt und ergänzt es. SSO entscheidet, wer sich anmelden darf; SCIM hält die Kontoliste selbst mit Ihrem Verzeichnis synchron. Die meisten Kunden konfigurieren beides: SAML oder OIDC für die Authentifizierung, SCIM für die Provisionierung.

Die SCIM-Konfiguration kann nur von einem **Superuser** vorgenommen werden.

## Was SCIM in DefectDojo bewirkt

Wenn Sie einen Identity Provider über SCIM verbinden, kann dieser:

* DefectDojo-Benutzer erstellen, wenn jemandem die Anwendung zugewiesen wird
* Namen und E-Mail-Adressen aktualisieren, wenn sie sich im Verzeichnis ändern
* Benutzer deaktivieren, wenn ihnen die Zuweisung entzogen wird oder sie die Organisation verlassen
* Gruppen erstellen sowie deren Mitglieder hinzufügen und entfernen

Das Deaktivieren eines Benutzers über SCIM bewirkt zwei Dinge gleichzeitig. Das Konto wird als inaktiv markiert, sodass sich der Benutzer nicht mehr anmelden kann, und die DefectDojo-API-Tokens des Benutzers werden gelöscht. Offboarding schließt damit beide Türen in einem einzigen Schritt – das ist der Hauptgrund, SCIM zu verwenden, statt sich allein auf Ihren Identity Provider zu verlassen.

Der Benutzerdatensatz selbst bleibt erhalten. Befunde, Notizen und der Verlauf verweisen auf die Personen, die sie erstellt haben, daher deaktiviert DefectDojo das Konto, anstatt es zu löschen. Kehrt dieselbe Person zurück, stellt die Reaktivierung über Ihren Identity Provider den Zugriff wieder her, ohne diesen Verlauf zu beeinträchtigen.

## Einrichtung

1. Öffnen Sie **Connect > Authorization** und wählen Sie **SCIM Provisioning**. SCIM wird zusammen mit Ihren Login-Providern aufgeführt, da es sich mit demselben Identity Provider verbindet, und ist mit **Provisioning** gekennzeichnet, um es von den Providern zu unterscheiden, die eine Schaltfläche auf der Anmeldeseite anzeigen.

2. Aktivieren Sie **Enable SCIM Provisioning** und übernehmen Sie die Änderung. Solange dies deaktiviert ist, verhalten sich die SCIM-Endpunkte so, als würden sie nicht existieren, sodass ein Verbindungstest von Ihrem Identity Provider die Adresse als nicht gefunden meldet.

3. Kopieren Sie die auf der Seite angezeigte **Tenant URL**. Sie sieht folgendermaßen aus:

   ```
   https://<your-instance>.cloud.defectdojo.com/scim/v2
   ```

4. Geben Sie dem Token im Bereich **SCIM Tokens** einen Namen, der angibt, wo es verwendet wird, zum Beispiel „Okta production", und wählen Sie dann **Generate Token**.

5. Kopieren Sie das Token aus dem Dialog und fügen Sie es in Ihren Identity Provider ein. DefectDojo speichert nur einen Hash des Tokens, sodass es nicht erneut angezeigt werden kann. Falls Sie es verlieren, generieren Sie ein neues und widerrufen Sie das alte.

Sie können mehrere Tokens gleichzeitig aktiv halten. Um ein Token zu rotieren, generieren Sie ein neues, aktualisieren Sie Ihren Identity Provider und widerrufen Sie anschließend das alte. Es gibt keinen Zeitraum, in dem die Provisionierung nicht funktioniert.

Das Token-Panel zeichnet auf, wann jedes Token zuletzt verwendet wurde – eine schnelle Möglichkeit zu prüfen, ob Ihr Identity Provider DefectDojo tatsächlich erreicht.

## Okta

1. Gehen Sie in der Okta Admin Console zu **Applications > Browse App Catalog** und fügen Sie **SCIM 2.0 Test App (Header Auth)** hinzu. Wenn Sie bereits eine SAML-Anwendung für DefectDojo haben, können Sie die Provisionierung stattdessen für diese Anwendung aktivieren.

2. Öffnen Sie den Tab **Provisioning** und wählen Sie **Configure API Integration**.

3. Setzen Sie **SCIM 2.0 Base Url** auf die oben kopierte Tenant URL.

4. Setzen Sie **API Token** auf `Bearer <your token>`, einschließlich des Worts `Bearer` und eines einzelnen Leerzeichens. Dieser Anwendungstyp sendet den Wert unverändert als Authorization-Header.

5. Wählen Sie **Test API Credentials** und speichern Sie anschließend.

6. Aktivieren Sie unter **Provisioning > To App** die Optionen **Create Users**, **Update User Attributes** und **Deactivate Users**.

7. Weisen Sie der Anwendung Personen oder Gruppen zu. Okta sucht jede Person zunächst anhand des Benutzernamens in DefectDojo und erstellt nur dann ein Konto, wenn keines gefunden wird. Wer bereits ein DefectDojo-Konto hat, wird also verknüpft statt dupliziert.

Um auch Gruppen zu übertragen, öffnen Sie den Tab **Push Groups** und fügen Sie die Gruppen hinzu, die DefectDojo spiegeln soll. Siehe [Gruppen](#groups) weiter unten für das, was DefectDojo damit macht.

## Microsoft Entra ID

1. Gehen Sie im Entra Admin Center zu **Enterprise applications > New application > Create your own application** und wählen Sie die Non-Gallery-Option. Wenn Sie bereits eine Anwendung für DefectDojo haben, verwenden Sie diese.

2. Öffnen Sie **Provisioning** und setzen Sie **Provisioning Mode** auf **Automatic**.

3. Setzen Sie **Tenant URL** auf die oben kopierte Tenant URL.

4. Setzen Sie **Secret Token** auf Ihr SCIM-Token. Entra sendet es als Bearer-Token, fügen Sie hier also nicht das Wort `Bearer` hinzu.

5. Wählen Sie **Test Connection** und speichern Sie anschließend.

6. Weisen Sie unter **Users and groups** Benutzer und Gruppen zu und starten Sie die Provisionierung.

Entra provisioniert in einem Zyklus von etwa 40 Minuten. Während der Einrichtung wendet **Provision on demand** einen einzelnen Benutzer oder eine Gruppe sofort an, was die Überprüfung der Konfiguration erheblich beschleunigt.

## Was DefectDojo speichert

DefectDojo ordnet eine kleine Menge an SCIM-Attributen zu und ignoriert den Rest.

| SCIM-Attribut | DefectDojo-Feld |
|---|---|
| `userName` | Username |
| `name.givenName` | First name |
| `name.familyName` | Last name |
| `emails` | Email address |
| `active` | Ob das Konto aktiviert ist |
| `externalId` | Wird gespeichert, damit Ihr Identity Provider den Datensatz später zuordnen kann |

Attribute, die DefectDojo nicht abbildet, darunter Telefonnummern, Jobtitel und die SCIM Enterprise Extension, werden akzeptiert und ignoriert statt abgelehnt. Das Mappen zusätzlicher Attribute in Ihrem Identity Provider ist unbedenklich.

Zwei Attribute verdienen besondere Aufmerksamkeit:

**Username.** DefectDojo erlaubt in einem Benutzernamen Buchstaben, Ziffern und die Zeichen `@ . + - _`. Wenn Ihr Identity Provider einen Benutzernamen mit anderen Zeichen sendet, lehnt DefectDojo diesen Benutzer mit einer Fehlermeldung ab, die das Problem benennt, statt stillschweigend einen abweichenden Benutzernamen zu speichern. Das Speichern eines veränderten Benutzernamens würde die Fähigkeit Ihres Providers beeinträchtigen, das Konto später wiederzufinden.

**Email address.** SCIM erfordert keine E-Mail-Adresse, und DefectDojo erstellt den Benutzer auch ohne sie. Bedenken Sie, dass DefectDojo-Benachrichtigungen, einschließlich geplanter Berichte und Alarme, für einen Benutzer ohne E-Mail-Adresse ins Leere laufen. Mappen Sie das Attribut `emails`, sofern Sie keinen Grund haben, dies nicht zu tun.

SCIM setzt niemals Passwörter und gewährt niemals Superuser- oder Staff-Status. Wenn Ihr Identity Provider so konfiguriert ist, dass er Passwörter sendet, ignoriert DefectDojo diese. Auf diese Weise bereitgestellte Benutzer melden sich über SSO an.

## Gruppen

SCIM verwaltet nur die Gruppen, die es selbst erstellt hat. Gruppen, die Sie in der DefectDojo-Benutzeroberfläche angelegt haben oder die über SAML- oder Azure-AD-Group-Mapping entstanden sind, sind für SCIM unsichtbar und können von Ihrem Identity Provider weder umbenannt noch geleert oder gelöscht werden.

Das ist wichtig, weil Group Push seiner Natur nach ein vollständiger Ersatz ist. Könnte ein Identity Provider eine bestehende Gruppe übernehmen, würde seine nächste Synchronisierung die sorgfältig gewählte Mitgliedschaft dieser Gruppe durch das ersetzen, was im Verzeichnis steht. Das Übertragen einer Gruppe, deren Name bereits vergeben ist, schlägt daher mit einer Meldung fehl, die den Konflikt erklärt. Um eine bestehende Gruppe an Ihren Identity Provider zu übergeben, benennen Sie entweder eine der beiden um, oder löschen Sie die DefectDojo-Gruppe und lassen Sie den Provider sie neu erstellen.

Innerhalb einer von SCIM verwalteten Gruppe gehört die Mitgliedschaft Ihrem Identity Provider, die Rollen gehören DefectDojo:

* Ein neu hinzugefügtes Mitglied erhält die Rolle **Reader**.
* Wenn Sie jemanden in DefectDojo zu einer höheren Rolle befördern, lassen spätere Synchronisierungen diese Rolle unangetastet.
* Wer von Hand zu einer von SCIM verwalteten Gruppe hinzugefügt wird, wird bei der nächsten Synchronisierung wieder entfernt, da der Identity Provider die maßgebliche Quelle dafür ist, wer dazugehört.

Das Löschen einer Gruppe über SCIM entfernt die Gruppe und ihre Mitgliedschaften. Die Personen, die darin waren, werden dabei nie gelöscht.

## Schutz des Administratorzugriffs

Standardmäßig deaktiviert SCIM kein Superuser-Konto. Der häufigste Fehler bei jeder Provisionierungseinrichtung ist ein Identity Provider, dessen Geltungsbereich weiter gefasst ist als beabsichtigt, und Superuser sind der Weg, um bei Problemen wieder Zugriff auf DefectDojo zu erhalten.

Wenn Ihr Identity Provider auch Superuser verwalten soll, aktivieren Sie **Allow SCIM to deactivate superusers** auf der SCIM-Einstellungsseite. Selbst dann weigert sich DefectDojo, den letzten verbleibenden aktiven Superuser zu deaktivieren, sodass die Provisionierung die Instanz nicht ohne Administrator zurücklassen kann.

## Einschränkungen

* Ein Identity Provider pro DefectDojo-Instanz.
* Filterung wird für `userName`, `displayName`, `externalId` und `id` mit einem einzelnen Gleichheitsvergleich unterstützt. Das deckt ab, was Okta und Entra beim Abgleich von Datensätzen senden. Komplexere Filter werden mit einer entsprechenden Fehlermeldung abgelehnt.
* Bulk-Operationen, Sortierung und der `/Me`-Endpunkt sind nicht implementiert.
* Gruppenmitgliedschaften werden über den Groups-Endpunkt verwaltet. Das Senden der Gruppenmitgliedschaft in einem Benutzerdatensatz hat keine Wirkung, was dem Verhalten beider Provider entspricht.

## Fehlerbehebung

**Der Verbindungstest meldet „not found".** SCIM ist deaktiviert, oder die Instanz ist nicht dafür lizenziert. Prüfen Sie, ob **Enable SCIM Provisioning** aktiviert ist und Ihr Abonnement SSO enthält. Solange nicht beides zutrifft, verhält sich die gesamte SCIM-Adresse so, als würde sie nicht existieren.

**Der Verbindungstest meldet einen Authentifizierungsfehler.** Das Token ist falsch oder wurde widerrufen. Generieren Sie ein neues und aktualisieren Sie Ihren Identity Provider. Prüfen Sie in Okta, dass der Wert mit `Bearer ` und einem Leerzeichen beginnt; prüfen Sie in Entra, dass dies nicht der Fall ist.

**Ein Benutzer kann nicht mit einer Fehlermeldung zum Benutzernamen provisioniert werden.** Der Benutzername enthält Zeichen, die DefectDojo nicht zulässt. Ändern Sie das Attribut, das Ihr Identity Provider auf `userName` mappt, meist auf die E-Mail-Adresse oder den User Principal Name des Benutzers.

**Eine Gruppe kann nicht übertragen werden, mit der Meldung, dass eine Gruppe dieses Namens bereits existiert.** Eine DefectDojo-Gruppe mit diesem Namen wurde an anderer Stelle erstellt. Siehe [Gruppen](#groups) weiter oben.

**Ein Gruppenmitglied kann nicht provisioniert werden.** Die Person wurde noch nicht für DefectDojo provisioniert. Weisen Sie sie der Anwendung zu; die Mitgliedschaft wird beim nächsten Zyklus erfolgreich übernommen.

**Beginnen Sie mit Diagnostics.** Abgelehnte SCIM-Anfragen werden unter **Connect > Diagnostics** aufgezeichnet, mit dem Endpunkt, dem Status und der von DefectDojo zurückgesendeten Meldung. Das ist meist schneller, als das Log Ihres Identity Providers zu lesen, und es ist die einzige Stelle, die beide Seiten des Austauschs zeigt. Erfolgreiche Provisionierung wird dort nicht aufgezeichnet; Änderungen an Benutzern und Gruppen erscheinen stattdessen im Audit-Verlauf.

**Alles meldet Erfolg, aber in DefectDojo erscheint nichts.** Prüfen Sie, dass die Tenant URL auf `/scim/v2` endet, ohne abschließenden Schrägstrich, und dass Ihr Identity Provider Ihre Instanz tatsächlich erreicht. Die Spalte **Last Used** im SCIM-Tokens-Panel zeigt, ob überhaupt eine Anfrage eingegangen ist.

**DefectDojo-Pro-Benutzer:** Wenn Ihre Instanz den Zugriff nach IP-Adresse einschränkt, fügen Sie die Adressen Ihres Identity Providers vor der Konfiguration von SCIM zur Firewall-Allowlist hinzu. Siehe [Firewall-Regeln](/get_started/pro/cloud/using-cloud-manager/#changing-your-firewall-settings).
