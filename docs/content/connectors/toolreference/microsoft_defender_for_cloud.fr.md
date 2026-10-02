---
title: "Microsoft Defender for Cloud"
description: "Comment configurer le Connecteur Upstream Microsoft Defender for Cloud pour DefectDojo"
weight: 90
audience: pro
---
Le connecteur Microsoft Defender for Cloud importe les constatations de vulnérabilités de **Microsoft Defender Vulnerability Management (MDVM)** telles qu'exposées par Defender for Cloud — à la fois les constatations **serveur** (CVE du système d'exploitation et des logiciels installés sur les VM Azure) et les constatations **registre de conteneurs** (CVE des images de conteneurs), incluant la sévérité, le score CVSS, le paquet ou l'image concerné, et la remédiation. DefectDojo découvre les **abonnements** Azure que votre service principal peut lire et crée un Record pour chaque abonnement activé.

**Remarque :** ce Connecteur est distinct du connecteur **Microsoft Defender**, qui importe les constatations d'appareils depuis l'API Defender for Endpoint. Defender for Cloud est un produit Azure avec une surface d'API différente (Azure Resource Manager / Resource Graph) et un modèle de permissions différent (Azure RBAC). Exécutez celui qui correspond à l'emplacement de vos constatations — ou les deux, si vous utilisez les deux produits.

#### Prérequis

Vous avez besoin d'un ou plusieurs **abonnements Azure avec Microsoft Defender for Cloud activé**, avec les plans Defender pertinents activés pour les ressources que vous souhaitez scanner (sous **Microsoft Defender for Cloud \> Environment settings**, puis sélectionnez votre abonnement) :

* **Defender for Servers (Plan 2)** — constatations CVE du système d'exploitation et des logiciels des VM Azure (scan de vulnérabilités sans agent).
* **Defender for Containers** — constatations CVE des images du registre de conteneurs.

Les constatations d'évaluation de vulnérabilités SQL et de configuration/posture ne sont intentionnellement **pas** importées — ce connecteur importe uniquement les vulnérabilités CVE.

Le connecteur s'authentifie en tant qu'**app registration** Microsoft Entra ID via le flux client credentials :

1. Dans le [portail Azure](https://portal.azure.com), ouvrez **App registrations \> New registration**. Nommez\-la (par exemple `defectdojo-connector`), laissez les valeurs par défaut, puis sélectionnez **Register**.
2. Sur la page **Overview** de l'application, notez l'**Application (client) ID** et le **Directory (tenant) ID**.
3. Ouvrez **Certificates & secrets \> New client secret**, définissez une expiration, et copiez immédiatement la **Value** du secret (elle n'est affichée qu'une seule fois). Le Connecteur cesse de fonctionner à l'expiration du secret, notez donc la date.
4. Accordez à l'application un accès en lecture à chaque abonnement que vous souhaitez importer : ouvrez **Subscriptions**, sélectionnez votre abonnement, puis **Access control (IAM) \> Add \> Add role assignment**. Sélectionnez le rôle **Security Reader** (ou **Reader**), et dans l'onglet **Members**, assignez\-le à l'application que vous avez créée — recherchez\-la par le **nom** ou l'**object ID** de l'application, car le sélecteur ne fait pas correspondre le client ID. Répétez l'opération pour chaque abonnement.

Contrairement au connecteur Microsoft Defender basé sur les appareils, aucune permission API ni consentement admin n'est requis : l'accès à Defender for Cloud est entièrement régi par l'attribution de rôle Azure RBAC ci\-dessus.

#### Correspondances du connecteur

1. Saisissez `https://management.azure.com` dans le champ **Location**. (Pour les clouds souverains, utilisez le endpoint ARM correspondant, par exemple `https://management.usgovcloudapi.net`.)
2. Saisissez le **Directory (tenant) ID** dans le champ **Tenant ID**.
3. Saisissez l'**Application (client) ID** dans le champ **Client ID**.
4. Saisissez la valeur du secret client dans le champ **Client Secret**.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque abonnement Azure activé devient un Record. Les constatations sont lues via Azure Resource Graph, elles apparaissent donc rapidement une fois que Defender for Cloud a scanné vos ressources — mais les scans eux\-mêmes s'exécutent selon le calendrier de Microsoft : les images du registre de conteneurs sont généralement scannées dans l'heure suivant leur push, tandis que le premier scan de vulnérabilités sans agent d'une VM peut prendre plusieurs heures. Un abonnement nouvellement activé effectuera légitimement un Sync avec zéro constatation tant que ses ressources n'auront pas été scannées.
