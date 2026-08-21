---
title: KeyCloak
description: Konfigurieren Sie KeyCloak SSO in DefectDojo Pro
weight: 13
audience: pro
---

DefectDojo Pro unterstützt die Anmeldung über KeyCloak. Open-Source-DefectDojo enthält kein SSO — siehe [Authorized Users](/admin/user_management/os__authorized_users/) für die Zugriffskontrolle in der Open-Source-Version.

Diese Anleitung setzt voraus, dass bereits ein KeyCloak Realm eingerichtet ist. Falls nicht, siehe die [KeyCloak-Dokumentation](https://wjw465150.gitbooks.io/keycloak-documentation/content/server_admin/topics/realms/create.html).

## Voraussetzungen

Führen Sie die folgenden Schritte in Ihrem KeyCloak-Realm aus, bevor Sie DefectDojo konfigurieren:

1. Fügen Sie einen neuen Client vom Typ `openid-connect` hinzu. Notieren Sie sich die Client-ID.

2. In den Client-Einstellungen:
   - Setzen Sie **Access Type** auf `confidential`
   - Fügen Sie unter **Valid Redirect URIs** Ihre DefectDojo-URL hinzu, z. B. `https://yourorganization.cloud.defectdojo.com` oder `https://your-dojo-host/*`
   - Fügen Sie unter **Web Origins** dieselbe URL hinzu (oder `+`)
   - Unter **Fine Grained OpenID Connect Configuration**:
     - Setzen Sie **User Info Signed Response Algorithm** auf `RS256`
     - Setzen Sie **Request Object Signature Algorithm** auf `RS256`
   - Speichern Sie die Einstellungen.

3. Setzen Sie unter **Scope** die Option **Full Scope Allowed** auf `off`.

4. Fügen Sie unter **Mappers** einen benutzerdefinierten Mapper hinzu:
   - **Name:** `aud`
   - **Mapper Type:** `audience`
   - **Included Audience:** wählen Sie Ihre Client-ID aus
   - **Add ID to Token:** `off`
   - **Add Access to Token:** `on`

5. Kopieren Sie unter **Credentials** das **Secret**.

6. Kopieren Sie unter **Realm Settings > Keys** den **Public Key** (Signaturschlüssel).

7. Öffnen Sie unter **Realm Settings > General > Endpoints** die OpenID-Endpunktkonfiguration und kopieren Sie die URLs der **Authorization**- und **Token**-Endpunkte.

## Konfiguration

Gehen Sie in DefectDojo zu **Enterprise Settings > OAuth Settings**, wählen Sie **KeyCloak** aus und füllen Sie das Formular aus:

- **KeyCloak OAuth Key** — geben Sie Ihren Clientnamen ein (aus Schritt 1)
- **KeyCloak OAuth Secret** — geben Sie das Secret der Client-Anmeldedaten ein (aus Schritt 5)
- **KeyCloak Public Key** — geben Sie den Public Key aus Ihren Realm-Einstellungen ein (aus Schritt 6)
- **KeyCloak Resource** — geben Sie die URL des Authorization-Endpunkts ein (aus Schritt 7)
- **KeyCloak Group Limiter** — geben Sie die URL des Token-Endpunkts ein (aus Schritt 7)
- **KeyCloak OAuth Login Button Text** — wählen Sie den Text für die DefectDojo-Anmeldeschaltfläche

Aktivieren Sie **Enable KeyCloak OAuth** und senden Sie das Formular ab. Auf der Anmeldeseite erscheint eine Anmeldeschaltfläche mit dem von Ihnen konfigurierten Text.
