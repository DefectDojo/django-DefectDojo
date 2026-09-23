---
title: "OpenVAS / Greenbone"
description: "Comment configurer le Connecteur Upstream OpenVAS / Greenbone pour DefectDojo"
weight: 98
audience: pro
---
Le connecteur OpenVAS / Greenbone importe les **constatations de vulnérabilités réseau** d'une instance Greenbone (Greenbone Community Edition ou Greenbone Enterprise). Il communique avec `gvmd` via **GMP (Greenbone Management Protocol)** — un protocole XML sur un socket TLS, et non HTTP — et synchronise l'instance entière : il énumère les **tâches** de scan et crée un produit DefectDojo pour chacune, en important les résultats du dernier rapport de chaque tâche.

#### Prérequis

Un **utilisateur GMP** Greenbone (nom d'utilisateur + mot de passe) et un accès réseau au port TLS GMP de gvmd (par défaut **9390**). La pile compose de Greenbone Community Edition expose gvmd via un socket unix ; pour l'atteindre depuis un connecteur en réseau, exécutez donc le connecteur là où il peut accéder au socket, ou exposez le port TLS GMP (par exemple un pont TLS `socat` vers `gvmd.sock`).

#### Correspondances du connecteur

1. Saisissez l'hôte gvmd dans le champ **Location** (hôte ou `host:port`).
2. Saisissez le **Username** et le **Password** GMP.
3. Optionnellement, définissez le **GMP Port** (par défaut 9390).
4. Pour le certificat auto\-signé par défaut de gvmd, fournissez soit un **CA Certificate (PEM)** pour la vérification, soit réglez **Skip TLS Verification** sur `true`.
5. Optionnellement, définissez une **Minimum Severity** pour limiter les constatations importées.

Chaque tâche Greenbone devient un Record. Les constatations proviennent du dernier rapport terminé de la tâche — une par `<result>`. La sévérité est tirée du niveau de menace du résultat (les niveaux informationnels `Log`/`Debug` de Greenbone sont associés à Info), avec le score CVSS numérique enregistré ; les références CVE deviennent des identifiants de vulnérabilité, la solution du NVT devient la mitigation, et l'hôte/port de chaque résultat devient un point de terminaison.
