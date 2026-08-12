---
title: Den Cloud Manager verwenden
description: Verwalten Sie Ihr Abonnement und Ihre Kontoeinstellungen
weight: 1
collapsed: true
audience: pro
aliases:
- /de/en/cloud_management/using-cloud-manager
---

Nach der Anmeldung im Cloud Manager von DefectDojo können Sie Ihre Kontoeinstellungen konfigurieren und Ihr Abonnement bei DefectDojo Cloud verwalten.

## **New Subscription**
<https://cloud.defectdojo.com/accounts/onboarding/step_1>

Auf dieser Seite können Sie eine neue [oder zusätzliche](../additional-cloud-instance/) Cloud-Instanz bei DefectDojo anfordern. 

## **Manage Subscriptions**
<https://cloud.defectdojo.com/accounts/manage_subscriptions>

Die Seite zur Abonnementverwaltung zeigt alle aktuell aktiven Cloud-Instanzen und erlaubt es Ihnen, die Firewall-Einstellungen für jede Instanz zu konfigurieren.

### Firewall-Einstellungen ändern
![image](images/using_the_cloud_manager.png)

Geben Sie auf der Seite **Edit Subscription** die IP-Adresse, die Maske und das Label für die Regel ein, die Sie hinzufügen möchten. Wenn mehr als eine Firewall-Regel benötigt wird, klicken Sie auf **Add New Range**, um eine neue leere Regel zu erstellen.

![image](images/using_the_cloud_manager_2.png)

Hier können Sie Ihre Firewall auch für externe Dienste öffnen (GitHub und Jira Cloud).  Sie können die Firewall auf Wunsch auch vollständig deaktivieren, indem Sie im Menü **Proceed Without Firewall** auswählen.

## Weitere Benutzer zum Cloud Portal hinzufügen

Wenn Sie mehreren Benutzern die Kontrolle über Ihr Cloud Portal beziehungsweise Ihr DefectDojo-Abonnement geben möchten, können Sie sie über dieses Formular hinzufügen.  Die Benutzer, die Sie hinzufügen möchten, müssen zuvor selbst ein Konto im Cloud Portal unter cloud.defectdojo.com erstellt haben. Ein Konto auf Ihrer DefectDojo-Instanz genügt nicht.

![image](images/using_the_cloud_manager_5.png)

Geben Sie die E-Mail-Adresse ein, die mit dem Cloud Portal-Konto des Benutzers verknüpft ist, und klicken Sie auf Submit, um ihn Ihrer Liste der verknüpften Benutzer hinzuzufügen.  Der Benutzer kann nun das Cloud Portal und Ihr DefectDojo-Abonnement verwalten.

## Resources
<https://cloud.defectdojo.com/resources/>

Die Seite „Resources" enthält ein Kontaktformular (Contact Us), über das Sie unser Support-Team erreichen können.

![image](images/using_the_cloud_manager_3.png)

## Tools
<https://cloud.defectdojo.com/external_tools/defectdojo-cli>

Auf der Seite „Tools" können Sie unter anderem externe Pro-Tools wie Universal Importer oder DefectDojo CLI herunterladen.  Diese Tools sind externe Add-ons, mit denen Sie schnell eine Import-Pipeline auf der Kommandozeile in Ihrem Netzwerk aufbauen können. Weitere Informationen zu diesen Tools finden Sie in der Dokumentation zu [External Tools](/import_data/pro/specialized_import/external_tools/).

![image](images/using_the_cloud_manager_6.png)


## Kontoeinstellungen
<https://cloud.defectdojo.com/accounts/settings>

Die Seite mit den Kontoeinstellungen besteht aus vier Abschnitten:

* **User Contact**: Hier legen Sie Benutzername, E-Mail-Adresse, Vornamen und Nachnamen fest.
* **Email Accounts**: Hier fügen Sie Ihrem Konto weitere E-Mail-Adressen hinzu. Beim Hinzufügen einer weiteren E-Mail-Adresse wird eine Bestätigungs-E-Mail an die neue Adresse gesendet.
* **Manage Social Accounts**: Hier verbinden Sie DefectDojo Cloud mit Ihren GitHub- oder Google-Anmeldedaten, mit denen Sie sich anstelle von Benutzername und Passwort anmelden können.
* **MFA Settings**: Hier fügen Sie einen MFA-Code zu Google Authenticator, 1Password oder ähnlichen Apps hinzu. Ein zusätzlicher Schritt im Anmeldevorgang ist eine gute proaktive Maßnahme gegen unbefugten Zugriff.

### MFA für Ihre Anmeldung im Cloud Portal hinzufügen
<https://cloud.defectdojo.com/settings/mfa/configure/>

Beachten Sie, dass MFA damit nur für Ihre Anmeldung bei DefectDojo Cloud gilt, nicht für die Anmeldung in Ihrer DefectDojo-App.

![image](images/using_the_cloud_manager_4.png)

1. Installieren Sie zunächst eine Authenticator-App auf Ihrem Smartphone oder Computer, die QR-Code-Authentifizierung unterstützt.
2. Klicken Sie anschließend auf **Generate QR Code**.
3. Scannen Sie den in DefectDojo angezeigten QR-Code mit Ihrer Authenticator-App und geben Sie dann den sechsstelligen Code aus Ihrer App ein.
4. Klicken Sie auf **Enable Multi-Factor Authentication**.
