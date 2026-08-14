---
title: SAML-Konfiguration
description: SAML in DefectDojo Pro konfigurieren
weight: 1
audience: pro
---

DefectDojo Pro unterstützt die SAML-Authentifizierung über die Benutzeroberfläche **Enterprise Settings**. Open-Source-DefectDojo enthält kein SSO – siehe [Autorisierte Benutzer](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in Open-Source-DefectDojo.

## ACS-URL (Assertion Consumer Service)

Ihr Identity Provider muss wissen, wohin er die SAML-Antwort nach der Authentifizierung eines Benutzers per POST senden soll. Die ACS-URL von DefectDojo lautet:

```
https://<your-instance>.cloud.defectdojo.com/saml2/acs/
```

Ein paar Dinge, die Sie zu diesem Endpunkt wissen sollten:

- **Der Endpunkt akzeptiert nur `POST`-Anfragen.** Wenn Sie die ACS-URL direkt im Browser öffnen, wird ein GET ausgelöst und es wird **HTTP 405 Method Not Allowed** zurückgegeben. Das ist erwartetes Verhalten – es bedeutet nicht, dass SAML fehlerhaft oder falsch konfiguriert ist. Der Endpunkt ist dafür vorgesehen, von Ihrem IdP im Rahmen des SAML-Redirect-Ablaufs aufgerufen zu werden, nicht durch Eingabe der URL in einem Browser.
- **Die ACS-URL ist auf Ihrer DefectDojo-Cloud-Instanz jederzeit verfügbar** – Sie müssen SAML in DefectDojo nicht zuerst aktivieren, bevor Sie Ihren IdP darauf verweisen. Sie können die IdP-Seite und die DefectDojo-Seite in beliebiger Reihenfolge konfigurieren.

## Einrichtung

1. Öffnen Sie **Enterprise Settings > SAML Settings**.

   ![image](images/sso_betaui_1.png)

2. Legen Sie eine **Entity ID** fest – eine Bezeichnung oder URL, mit der Ihr SAML Identity Provider DefectDojo identifiziert. Dieses Feld ist erforderlich.

3. Legen Sie optional den **Login Button Text** fest – den Text, der auf der Schaltfläche angezeigt wird, über die Benutzer die SAML-Anmeldung starten.

4. Legen Sie optional eine **Logout URL** fest, zu der Benutzer nach dem Abmelden von DefectDojo weitergeleitet werden.

5. Wählen Sie ein **Name ID Format**:
   - **Persistent** – Benutzer werden über SAML sitzungsübergreifend konsistent identifiziert.
   - **Transient** – Benutzer erhalten bei jeder Anmeldung eine andere SAML-ID.
   - **Entity** – alle Benutzer teilen sich eine einzige SAML-NameID.
   - **Encrypted** – die NameID jedes Benutzers wird verschlüsselt.

6. **Required Attributes** – legen Sie fest, welche Attribute DefectDojo aus der SAML-Antwort benötigt.

7. **Attribute Mapping** – ordnen Sie die von Ihrem IdP gesendeten Attribute den DefectDojo-Benutzerfeldern zu, die sie befüllen sollen. Jede Zeile verknüpft ein **SAML Attribute** mit einem **DefectDojo Field**; verwenden Sie **Add Attribute Mapping** für weitere Zeilen und das Papierkorb-Symbol, um eine Zeile zu entfernen.

   ![image](images/sso_saml_attribute_mapping.png)

   - **SAML Attribute** ist Freitext und muss genau dem Attributnamen entsprechen, den Ihr IdP tatsächlich sendet. Manche IdPs (z. B. Entra ID / Azure AD) senden vollqualifizierte Claim-URIs wie `http://schemas.microsoft.com/identity/claims/emailaddress` anstelle von benutzerfreundlichen Namen. Wenn Sie nicht sicher sind, was Ihr IdP sendet, aktivieren Sie **Enable SAML Debugging** (siehe [Troubleshooting](#troubleshooting)) und prüfen Sie die Assertion in den Logs.
   - **DefectDojo Field** wird aus einer Liste ausgewählt: **Username**, **First Name**, **Last Name** und **Email**.
   - Ordnen Sie mindestens das Attribut zu, das **Username** entspricht. DefectDojo sucht Benutzer anhand des Benutzernamens, wenn SAML-Anmeldungen bestehenden Konten zugeordnet werden.
   - Es wird dringend empfohlen, ein Attribut auf **Email** zu mappen: DefectDojo verwendet die E-Mail-Adresse für Benachrichtigungen und um eine eingehende Anmeldung anhand der E-Mail-Adresse einem bestehenden Konto zuzuordnen.
   - Dasselbe Attribut kann mehrere Felder speisen – zum Beispiel ein E-Mail-Claim, der sowohl für **Email** als auch für **Username** verwendet wird. Umgekehrt ist das nicht zulässig: Jedes DefectDojo-Feld darf nur von einem Attribut zugeordnet werden.
   - Eine Zeile, bei der nur eine Hälfte ausgefüllt ist, wird beim Speichern abgelehnt, und die betroffene Zelle wird hervorgehoben. Zeilen, die Sie hinzufügen, aber nie ausfüllen, werden verworfen und nicht als Fehler behandelt.

8. **Remote SAML Metadata** – die URL, unter der die Metadaten Ihres SAML Identity Providers gehostet werden.

9. Aktivieren Sie **Enable SAML** am unteren Rand des Formulars, um die SAML-Anmeldung zu aktivieren. Auf der DefectDojo-Anmeldeseite erscheint dann eine Schaltfläche **Login With SAML**.

   ![image](images/sso_saml_login.png).

## Weitere Optionen

* **Create Unknown User** – erstellt automatisch einen neuen DefectDojo-Benutzer, wenn dieser in der SAML-Antwort nicht gefunden wird.
* **Allow Unknown Attributes** – erlaubt die Anmeldung für Benutzer, deren Attribute nicht im Attribute Mapping aufgeführt sind.
* **Sign Assertions/Responses** – verlangt, dass alle eingehenden SAML-Antworten signiert sind.
* **Sign Logout Requests** – signiert alle von DefectDojo gesendeten Logout-Anfragen.
* **Force Authentication** – verlangt, dass sich Benutzer bei jeder Anmeldung erneut beim Identity Provider authentifizieren, unabhängig von bestehenden Sitzungen.
* **Enable SAML Debugging** – protokolliert detaillierte SAML-Ausgaben zur Fehlerbehebung. Siehe [Troubleshooting → SAML Debugging output](#saml-debugging-output), wo diese Log-Ausgabe erscheint.

## SAML-Gruppenzuordnung

DefectDojo kann die SAML-Assertion nutzen, um Benutzer automatisch [Benutzergruppen](../../user_management/create_user_group/) zuzuweisen. Gruppen in DefectDojo weisen allen ihren Mitgliedern Berechtigungen zu, sodass Sie mit Group Mapping Berechtigungen im großen Stil verwalten können. Dies ist der einzige Weg, Berechtigungen über SAML festzulegen.

**Group Mapping ist optional.** Obwohl die Felder **Group Name Attribute** und **Group Limiter Regex Expression** in der Benutzeroberfläche mit einem Pflichtfeld-Sternchen (`*`) versehen sind, kann das SAML-Formular auch ohne sie abgeschickt werden, und die SAML-Anmeldung funktioniert auch ohne Group Mapping. Sie müssen in Ihrem IdP (z. B. Azure-AD-Anwendungsrollen) keine Gruppen oder Rollen vorab anlegen, bevor Sie SAML aktivieren – Sie müssen diese Felder nur konfigurieren, wenn DefectDojo die Gruppenmitgliedschaft tatsächlich aus der Assertion auslesen soll. Wenn Sie kein Group Mapping konfigurieren, haben neu erstellte SSO-Benutzer standardmäßig keine Berechtigungen; siehe [Standardzugriff für per SSO bereitgestellte Benutzer](#default-access-for-sso-provisioned-users) weiter unten.

Das Feld **Group Name Attribute** legt fest, welches Attribut in der SAML-Assertion die Gruppenmitgliedschaften des Benutzers enthält. Wenn sich ein Benutzer anmeldet, liest DefectDojo dieses Attribut aus und weist den Benutzer allen passenden Gruppen zu. Um einzuschränken, welche Gruppen aus der Assertion berücksichtigt werden, verwenden Sie das Feld **Group Limiter Regex Expression** – ein regulärer Ausdruck, der auf die Gruppennamen aus der Assertion angewendet wird, um zu filtern, welche davon DefectDojo berücksichtigen soll.

Der Wert muss exakt dem Attributnamen entsprechen, den Ihr Identity Provider in der Assertion sendet, einschließlich eines eventuellen Namespace-Präfixes. Ein kurzer, benutzerfreundlicher Name wie `groups` funktioniert nur, wenn Ihr IdP so konfiguriert ist, dass er genau diesen Attributnamen sendet – viele IdPs verwenden stattdessen eine vollqualifizierte Claim-URI.

### Group Name Attribute je Identity Provider

| Identity Provider | Zu verwendender Standard-Attributname |
|---|---|
| **Entra ID / Azure AD** | `http://schemas.microsoft.com/ws/2008/06/identity/claims/groups` |
| **Okta** | `groups` (der Attributname, den Sie im Group Attribute Statement der SAML-App konfiguriert haben) |
| **Keycloak** | `groups` (oder der Wert, den Sie als „SAML Attribute Name" im Group-List-Mapper festgelegt haben) |
| **PingFederate / generisch** | Der Wert, den Sie auf der IdP-Seite konfiguriert haben – prüfen Sie die Assertion Ihres IdP, bevor Sie `groups` annehmen |

Wenn Group Mapping scheinbar nichts bewirkt – Benutzer melden sich erfolgreich an, aber es werden keine Gruppen erstellt oder zugewiesen – siehe [Troubleshooting → SAML group mapping does nothing](#saml-group-mapping-does-nothing--users-log-in-but-no-groups-are-assigned) weiter unten.

Wenn keine Gruppe mit passendem Namen existiert, erstellt DefectDojo automatisch eine und weist ihren Mitgliedern die Rolle **Reader** zu. Beachten Sie, dass diese Reader-Rolle den Zugriff des Mitglieds *auf die Gruppe selbst* regelt – sie gewährt keinen Zugriff auf zugrunde liegende Produkte, Produkttypen oder andere organisatorische Objekte. Diese Berechtigungen werden separat konfiguriert, und eine neu automatisch erstellte Gruppe hat zunächst keine davon, bis ein Superuser der Gruppe eine Rolle für die betreffenden Produkte oder Produkttypen zuweist.

Um Group Mapping zu aktivieren, aktivieren Sie das Kontrollkästchen **Enable Group Mapping** am unteren Rand des Formulars.

## Standardzugriff für per SSO bereitgestellte Benutzer

Wenn ein neuer Benutzer über SAML (oder einen anderen Social-Auth-Provider) erstellt und über kein SAML Group Mapping einer Gruppe hinzugefügt wird, landet er auf einer DefectDojo-Instanz **ohne Berechtigungen**. Er sieht nach der Anmeldung keine Produkttypen, keine Produkte und keine Engagements – das Dashboard erscheint leer.

Um jedem neu bereitgestellten SSO-Benutzer eine sinnvolle Ausgangsbasis zu geben, konfigurieren Sie auf der Seite System Settings eine **Default group** + **Default group role**:

1. Öffnen Sie **⚙️ Configuration → System Settings** (nur Superuser).
2. Setzen Sie **Default group** auf die [Benutzergruppe](../../user_management/create_user_group/), der neu erstellte Benutzer beitreten sollen.
3. Setzen Sie **Default group role** auf die Rolle, die sie in dieser Gruppe innehaben sollen (z. B. **Reader**).
4. Legen Sie optional **Default group email pattern** als regulären Ausdruck fest (z. B. `.*@yourcompany\.com$`), damit die Standardgruppe nur auf Benutzer angewendet wird, deren E-Mail-Adresse übereinstimmt.
5. Speichern.

Sowohl **Default group** als auch **Default group role** müssen gesetzt sein – ist eines der beiden leer, wird die Standardgruppe nicht angewendet.

Diese Einstellung gilt für **jeden neu erstellten Benutzer**, einschließlich Benutzern, die über SAML, OAuth und andere Social-Auth-Provider erstellt wurden, da sie auf Djangos User-Creation-Signal basiert und nicht innerhalb eines bestimmten Authentifizierungs-Backends läuft.

> **Bestehende Benutzer sind nicht betroffen.** Die Standardgruppe wird nur bei der erstmaligen Erstellung eines Benutzers angewendet. Bestehende DefectDojo-Benutzer behalten ihre aktuellen Gruppenmitgliedschaften, auch wenn Sie diese Einstellung später ändern.

## Unterschiede zwischen Cloud und On-Premise

DefectDojo Cloud bietet nicht denselben Grad an SAML-Anpassung wie DefectDojo On-Prem. Die einzigen Variablen, die gesetzt werden können, laufen über die Benutzeroberfläche. Hier sind einige der wichtigsten Unterschiede:

| Funktion | Cloud | On-Premise |
|---|---|---|
| **Username-Abgleich** | Nur NameID | Nur NameID (die Umgebungsvariable `SAML_USE_NAME_ID_AS_USERNAME` gilt nur für Open Source, nicht für Pro) |
| **Verschlüsselung der SAML-Assertion** | Derzeit nicht unterstützt | Derzeit nicht unterstützt |
| **SAML-Anmeldeprotokolle** | In der Benutzeroberfläche nicht verfügbar. Wenden Sie sich an den Support, um Protokolle anzufordern. | Verfügbar über die Anwendungs-Container-Logs (`docker logs dojo`) |
| **Konfigurationsmethode** | Nur Enterprise-Settings-UI | Enterprise-Settings-UI, Django Admin oder Django Shell |
| **Umgebungsvariablen** | Können von Kunden nicht direkt gesetzt werden. Wenden Sie sich für Änderungen an den Support. | Können über `dojo-compose-cli environment add` gesetzt werden |

Wenn Sie Benutzer anhand eines anderen Attributs als NameID abgleichen müssen (z. B. `uid` oder `email`), konfigurieren Sie Ihren Identity Provider so, dass er den gewünschten Wert als NameID sendet, anstatt die DefectDojo-Einstellungen anzupassen.

## Fehlerbehebung

### SAML-Debug-Ausgabe

Wenn **Enable SAML Debugging** (unter [Weitere Optionen](#additional-options)) aktiviert ist, schreibt DefectDojo detaillierte Ausgaben zur SAML-Verarbeitung – einschließlich der vom IdP empfangenen Rohattribute – auf der Stufe `DEBUG` unter dem Logger `saml2` in die Anwendungsprotokolle.

| Betriebsumgebung | Wo die Debug-Ausgabe zu finden ist |
|---|---|
| **DefectDojo Cloud** | Das SAML-Debug-Log ist in der Benutzeroberfläche nicht sichtbar. Wenden Sie sich an den DefectDojo-Support, um die Logs für einen bestimmten Zeitraum anzufordern. |
| **On-Premise (einzelner Container)** | `docker logs dojo` (oder Ihre Helm-/K8s-Log-Aggregation) |
| **On-Premise (Helm/K8s)** | `kubectl logs deployment/defectdojo-django -c uwsgi` (oder der Log-Aggregator Ihres Clusters) |

Schalten Sie diese Option nach Abschluss der Fehlerbehebung wieder **aus** – SAML-Debug-Logs sind ausführlich und können sensible Attributwerte Ihres IdP enthalten.

### Benutzer erhalten nach erfolgreicher IdP-Anmeldung die Fehlermeldung „User not found" oder „Permission denied"

Wenn die SAML-Assertion erfolgreich verarbeitet wird (keine XML- oder Signaturfehler), DefectDojo die Anmeldung aber verweigert, liegt die häufigste Ursache in einer **Diskrepanz beim Benutzernamen** zwischen IdP und DefectDojo.

DefectDojo sucht den Benutzer **anhand des Benutzernamens**, wenn eine SAML-Anmeldung einem bestehenden Konto zugeordnet wird. Wenn der Wert, den Ihr IdP als Attribut `username` sendet, nicht dem Benutzernamen eines bestehenden DefectDojo-Benutzers entspricht, schlägt die Suche fehl – auch wenn der Rest der Assertion gültig ist.

Zwei Abhilfen, wählen Sie diejenige, die zu Ihrer Umgebung passt:

- **Entfernen Sie `username` aus dem Attribute Mapping** und lassen Sie DefectDojo stattdessen auf die SAML-`NameID` als Benutzername zurückgreifen. Das ist sinnvoll, wenn Ihre DefectDojo-Benutzernamen bereits dem NameID-Format entsprechen, das Ihr IdP sendet.
- **Gleichen Sie die Benutzernamen an.** Stellen Sie sicher, dass die Benutzernamen in DefectDojo genau dem entsprechen, was Ihr IdP im Claim `username` sendet. Für die meisten Organisationen ist es am einfachsten, die DefectDojo-Benutzernamen der E-Mail-Adresse des Benutzers entsprechen zu lassen und den IdP die E-Mail-Adresse als `username`-Claim senden zu lassen.

Wenn Sie nicht sicher sind, was der IdP tatsächlich sendet, aktivieren Sie **Enable SAML Debugging** (siehe oben) und prüfen Sie die verarbeiteten Attribute in den Logs.

### SAML Group Mapping bewirkt nichts – Benutzer melden sich an, aber es werden keine Gruppen zugewiesen

Die häufigste Ursache ist eine Diskrepanz zwischen dem Feld **Group Name Attribute** und dem Attributnamen, den Ihr IdP tatsächlich sendet. Siehe die Tabelle [Group Name Attribute by Identity Provider](#group-name-attribute-by-identity-provider) weiter oben, und aktivieren Sie **Enable SAML Debugging**, um die vom IdP zurückgesendeten Rohattribute zu sehen.
