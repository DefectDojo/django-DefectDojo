---
title: Fehlerbehebung bei Verbindungsproblemen
description: Erneut mit Ihrer DefectDojo-Instanz verbinden
weight: 2
audience: pro
aliases:
- /en/cloud_management/connectivity-troubleshooting
---

Wenn Sie Schwierigkeiten haben, auf Ihre DefectDojo-Instanz zuzugreifen, finden Sie hier einige Schritte, mit denen Sie die Verbindung wiederherstellen können:

## Ich kann auf die Seite zugreifen, kann mich aber nicht anmelden

1. Sie können das Passwort für Ihr Konto über die Login-Seite zurücksetzen: **yourcompanyinstance.cloud.defectdojo.com/login**. Klicken Sie auf 'I forgot my password', um den Vorgang zu starten.  
​

![image](images/Connectivity_Troubleshooting.png)

2. Geben Sie Ihre E-Mail-Adresse ein und klicken Sie auf "Reset my password".  
​
3. Sie sollten eine E-Mail mit dem Betreff "`Password reset on yourcompanyinstance.cloud.defectdojo.com`" erhalten. Diese E-Mail enthält einen Link, über den Sie ein neues Passwort festlegen können.  
  

![image](images/Connectivity_Troubleshooting_2.png)

Wenn Sie keine E-Mail erhalten, überprüfen Sie bitte Ihren Spam-Ordner. Ist das ebenfalls erfolglos, lassen Sie sich vom DefectDojo-Admin Ihres Teams bestätigen, dass für Sie ein Konto auf Ihrer Instanz registriert ist.  



## Ich kann nicht auf die cloud.defectdojo-Seite meines Unternehmens zugreifen

Wenn die cloud.defectdojo-Seite Ihres Unternehmens in Ihrem Browser nicht lädt oder ein Timeout auftritt, muss Ihr Unternehmen unter Umständen die Firewall-Regeln anpassen, damit Ihre Verbindung akzeptiert wird.

Firewall-Regeln können in Ihrem Cloud Manager unter <https://cloud.defectdojo.com/accounts/manage_subscriptions> geändert werden.

Wenn Ihr Unternehmen ein gemeinsam genutztes VPN, einen Proxyserver oder ein ähnliches Tool verwendet, stellen Sie sicher, dass dieses für die Verbindung mit DefectDojo autorisiert ist und dass die IP-Adresse in den Firewall-Regeln von DefectDojo enthalten ist.

Wenn das Problem weiterhin besteht, wenden Sie sich bitte an [support@defectdojo.com](mailto:support@defectdojo.com) .



## Ich kann mich nicht beim Cloud Manager anmelden

Wenn Sie nicht auf den Cloud Manager zugreifen können, rufen Sie die Login-Seite unter <https://cloud.defectdojo.com/accounts/login/> auf und klicken Sie auf **„Forgot your password?“**


![image](images/Connectivity_Troubleshooting_3.png)  
Sie werden aufgefordert, Ihre E-Mail-Adresse einzugeben, und unser Team sendet Ihnen eine E-Mail mit einem Link, über den Sie Ihr Passwort zurücksetzen und ein neues eingeben können. 

Bitte beachten Sie, dass diese Anmeldemethode nur für den **Cloud Manager** funktioniert, eine Admin-Seite, auf die möglicherweise nicht alle Mitglieder Ihres Teams Zugriff haben. Die direkte Anmeldung an Ihrer Instanz zur Nutzung von DefectDojo ist nur durch direkte Verbindung mit **yourcompanyinstance.cloud.defectdojo.com/login** möglich.



## Ich habe keinen Zugriff mehr auf meine MFA-Codes

* **Für den Cloud Manager:** Wenn Sie den Zugriff auf Ihre MFA-Codes oder Ihre Authenticator-App verlieren, wenden Sie sich bitte an den DefectDojo Support unter [support@defectdojo.com](mailto:support@defectdojo.com).
* **Für eine DefectDojo-Instanz:** Versuchen Sie zunächst einen der **Wiederherstellungscodes**, die bei der MFA-Einrichtung ausgestellt wurden — geben Sie ihn bei der Anmeldung anstelle des sechsstelligen Codes ein. Sind diese nicht verfügbar, kann ein Administrator mit Server-Zugriff die MFA für das Konto mit `python manage.py remove_mfa --username <username>` zurücksetzen; der Benutzer meldet sich anschließend mit seinem Passwort an und richtet MFA erneut ein, wobei alle bestehenden Berechtigungen und der Verlauf erhalten bleiben. Wenden Sie sich bei DefectDojo Cloud an den Support, damit dieser Befehl ausgeführt wird. Die vollständigen Optionen finden Sie unter [Multi\-Faktor-Authentifizierung](/admin/user_management/pro__mfa/#recovering-a-user-who-has-lost-their-mfa-device).

