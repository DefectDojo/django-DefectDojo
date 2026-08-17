---
title: Renseignement sur les menaces
description: Les preuves d'exploit et de menace comme donnée de premier plan pour
  la Priorité et le Risque
weight: 2
audience: pro
---

DefectDojo Pro enrichit vos constatations avec un **renseignement sur les menaces dédié** — disponibilité d'exploit,
exploitation connue et activité d'acteurs de la menace — et l'intègre dans la Priorité
et le Risque. Cela va bien au-delà de l'EPSS et de l'indicateur CISA KEV.

## Ce que vous obtenez

Chaque constatation associée à un CVE est confrontée, chaque nuit, à un flux de renseignement organisé, constitué
à partir de CISA KEV, Metasploit, Exploit-DB, des modèles Nuclei et du suivi public des preuves de
concept. Lorsqu'il existe une preuve d'exploit, la constatation affiche une carte **Renseignement sur les menaces** :

* un badge de **maturité d'exploit** — *Aucune → PoC → Armé → Actif en conditions réelles*
* un **score de menace** (0–100)
* des **puces de preuve renvoyant à la source** — l'entrée KEV (avec sa date d'inscription),
  l'utilisation dans un ransomware, un module Metasploit, une entrée Exploit-DB, un modèle Nuclei, et des
  dépôts publics de preuves de concept
* une ligne en langage clair expliquant **pourquoi** la priorité de la constatation a augmenté

Au-delà de la carte, ce renseignement est exploité dans toute l'application :

* une **colonne Maturité d'exploit** sur la liste des constatations — triable et filtrable
  (par exemple, « Armé ou Actif uniquement »)
* une tuile **« Urgent et activement exploité »** sur le tableau de bord Priority Layout, comptant
  les constatations à risque Urgent activement exploitées en conditions réelles — cliquer dessus ouvre
  la liste des constatations filtrée exactement en conséquence
* un **événement de notification** (`threat_intel_alert`) lorsque le CVE d'une constatation existante gagne une nouvelle
  preuve d'exploit, par exemple en entrant dans CISA KEV ou en obtenant un module Metasploit. Seules les montées
  en niveau notifient — une preuve qui s'estompe discrètement ne déclenche jamais de notification.

## Comment cela modifie le calcul du score

Le moteur de Priorité combinait déjà la sévérité, le contexte métier et un « score externe »
construit à partir de l'EPSS + KEV. Le renseignement sur les menaces généralise ce score externe : chaque type de
preuve d'exploit agit comme un plancher sur l'échelle EPSS.

| Preuve | Plancher de Priorité (équivalent EPSS) |
|---|---|
| Exploitation active + ransomware/acteur nommé | 45% |
| Dans CISA KEV **et** utilisé dans un ransomware | 30% |
| Dans KEV ou exploité en conditions réelles | 20% |
| Exploit public armé (Metasploit / Exploit-DB) | 15% |
| Un modèle de détection Nuclei existe | 12% |
| Preuve de concept publique uniquement | 8% |
| Aucune preuve d'exploit | aucun changement |

Le score externe de la constatation correspond à la valeur **la plus élevée** entre sa valeur dérivée de l'EPSS et le plus
haut plancher de preuve ci-dessus — le renseignement ne fait donc jamais qu'*augmenter* un score, jamais le
baisser, et une constatation dont l'EPSS dépasse déjà le plancher n'est pas affectée. Le **facteur d'échelle du score externe**
habituel, par type de produit, dans les paramètres de votre Moteur de priorisation, met à l'échelle cette contribution
exactement comme il l'a toujours fait pour l'EPSS/KEV.

### Le plancher de Risque pour exploitation active

Le tableau ci-dessus augmente la **Priorité**, mais proportionnellement à la sévérité de base d'une constatation. Cela
a une conséquence qu'il vaut la peine de préciser clairement : une constatation de sévérité Faible portant un CVE qui est
exploité en conditions réelles ne reçoit qu'une petite hausse absolue, et pourrait donc rester dans une bande
**Risque** faible. La plupart des équipes considèrent que c'est incorrect — une « exploitation active » ne devrait jamais être classée
en Faible.

Il existe donc une seconde règle, catégorique celle-ci. Lorsque le renseignement sur les menaces signale une
**exploitation active en conditions réelles**, la Priorité de la constatation est relevée au moins au niveau
d'une bande de Risque configurée, indépendamment du résultat du calcul pondéré seul. Elle est livrée
configurée sur **Nécessite une action** ; chaque type de produit peut la relever jusqu'à Urgent, l'abaisser, ou la désactiver
pour couper ce plancher, dans les paramètres du Moteur de priorisation, sous *Plancher de Risque pour exploitation
active*.

Ce plancher ne fait qu'augmenter — il ne fait jamais redescendre une constatation, et une constatation qui
obtient déjà un score plus élevé par elle-même n'est pas touchée. Comme il s'applique à la Priorité, la bande de
Risque et le score de Risque en découlent automatiquement, de sorte que chaque liste, filtre, graphique et calcul de SLA
voit le même nombre cohérent.

## Constatations sans CVE

Le renseignement sur les menaces est mis en correspondance par CVE. De nombreuses constatations — la plupart des résultats SAST, secrets,
mauvaises configurations, règles personnalisées — n'ont pas de CVE, et aucun renseignement sur les menaces au niveau
d'une instance de vulnérabilité n'existe pour elles, nulle part (cela vaut pour tous les éditeurs, pas seulement DefectDojo).
Ces constatations :

* conservent **exactement** leur Priorité et leur Risque actuels — la fonctionnalité ne baisse jamais un score
* restent priorisées par toutes les autres données d'entrée du moteur (sévérité, criticité métier,
  exposition, etc.)
* affichent « Aucun renseignement sur les menaces disponible — cette constatation n'a pas de CVE à faire correspondre » sur
  la carte, ce qui la distingue d'une constatation avec CVE qui n'a simplement pas encore d'exploit connu

Une conséquence honnête : dans une file mixte, à mesure que les constatations porteuses d'un CVE gagnent des preuves d'exploit,
les constatations sans CVE reculent en rang *relatif*, même si leur score reste inchangé.

## Confiance et stabilité des scores

* **Renseignement signé.** Chaque lot nocturne est signé cryptographiquement par DefectDojo ;
  votre instance refuse les données altérées ou non signées. Les instances air-gap importent le même
  lot signé avec une étape de vérification hors ligne.
* **Pas d'oscillation de score.** Les montées en niveau de preuve s'appliquent la nuit où elles apparaissent. Si une source
  *perd* une preuve, les scores restent stables pendant une fenêtre de stabilité (14 jours par défaut) — un
  incident de flux ne fait jamais rebondir votre file, et les véritables désescalades s'installent discrètement une fois
  la fenêtre passée.
* **Prise en charge air-gap.** Le lot quotidien (y compris les données EPSS) peut être transféré et
  importé hors ligne, afin que les instances isolées bénéficient du même enrichissement.

## Déploiements auto-hébergés

Les instances DefectDojo Cloud ne nécessitent aucune configuration. Les instances auto-hébergées disposent de trois options :

* **Connecté (par défaut).** L'instance récupère le lot signé chaque nuit depuis
  `intel.defectdojo.com` via HTTPS. Il s'agit d'une destination qu'aucune autre fonctionnalité de DefectDojo
  n'utilise ; il faut donc généralement l'autoriser explicitement : ouvrez le port 443 sortant vers cet hôte, et sur
  Kubernetes, ajoutez-le à votre politique réseau de sortie (egress). Notez que la récupération s'exécute sur le **worker
  Celery**, et non sur le pod web ; les paramètres de proxy doivent donc aussi atteindre cette charge de travail.
* **Miroir interne.** Pointez `DD_THREAT_INTEL_BUNDLE_URL` (ainsi que les URL de digest et de
  signature correspondantes) vers un emplacement de votre réseau que vous synchronisez vous-même. La vérification de signature
  s'applique toujours, donc un miroir ne peut pas altérer les données.
* **Air-gap.** Transférez le lot et sa signature à la main, puis importez-les avec
  `manage.py load_threat_intel_bundle --file <bundle>`. La signature est vérifiée à l'importation.

Si l'instance ne peut pas atteindre le flux, la fonctionnalité échoue de façon sécurisée (fail closed) : l'exécution est enregistrée comme
échouée et vos scores et preuves existants restent exactement tels quels. Rien ne se dégrade
sinon la fraîcheur du renseignement.

## Activation

La fonctionnalité est désactivée par défaut à la livraison. Les administrateurs peuvent l'activer directement, ou d'abord l'exécuter
en **mode observation (shadow mode)** — qui calcule les scores potentiels sans rien modifier en production et
produit un rapport d'écart montrant exactement quelles constatations bougeraient — avant de l'activer réellement.
Contactez le support ou consultez le runbook d'exploitation pour connaître le déploiement recommandé sur les grandes
instances.
