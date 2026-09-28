---
title: Calendrier
description: Comment utiliser le calendrier dans DefectDojo Pro
audience: pro
weight: 9
---

DefectDojo propose un calendrier intégré qui vous permet de suivre tous les Engagements et Tests antérieurs et actifs au sein de votre organisation. Chaque fois qu'un Utilisateur crée un nouvel Engagement ou Test et définit les dates de début et de fin, une entrée correspondante est automatiquement ajoutée au calendrier. 

### Page d'accueil 

La page Calendrier comprend des filtres en haut et un calendrier mensuel en dessous. Les filtres permettent d'ajuster les résultats qui apparaissent dans le calendrier en fonction des critères suivants :
- Engagement et/ou Test 
- Date de début et de fin 
- Statut de l'Engagement (par exemple, Terminé, En cours, En attente, etc.) 
- Responsable de l'Engagement/Test (c'est-à-dire, à qui l'Engagement/Test est-il assigné ?) 
- Type d'Engagement (par exemple, Interactif ou CI/CD)
- Type de Test (par exemple, Pen Test, Acunetix Scan, Tenable Scan, etc.) 

![image](images/calendar1.png)
 
Une fois filtrés, les résultats peuvent être exportés et partagés sous forme de fichier ICS. 

Il est important de noter que le calendrier n'affichera que les Engagements et Tests auxquels l'Utilisateur consultant le calendrier a accès. Il n'affichera pas les Engagements et Tests que l'Utilisateur n'est pas autorisé à consulter. 

## Fonctionnalités 

### Vue mensuelle

Le calendrier mensuel affiche un aperçu de cinq entrées par jour. Les entrées supplémentaires survenant ce jour-là resteront masquées, sauf si vous cliquez sur **« + [X] événements »** dans la cellule de la date concernée. Une fois cliqué, le calendrier passe d'une vue mensuelle à une vue journalière.

Cliquer sur une entrée de Test ou d'Engagement ouvre une fenêtre modale contenant des informations supplémentaires sur cette entrée, notamment : 
- Date de début et de fin 
- Type de Test ou d'Engagement 
- Responsable 
- Statut 
- Actif 
- Engagement 
- Test 

À partir de là, il est possible d'accéder à l'Actif, à l'Engagement ou au Test via un lien hypertexte.

### Vue journalière 

Dans la vue journalière, tous les Engagements et Tests actuellement actifs apparaissent par ordre chronologique décroissant (c'est-à-dire qu'un Engagement ou Test nouvellement créé se trouvera en bas de la liste des entrées de ce jour). Les Engagements apparaissent en bleu, tandis que les Tests apparaissent en orange.

Si ces informations sont définies dans l'Engagement/Test concerné, le titre de chaque entrée du calendrier journalier inclura les éléments suivants :
- Statut 
- Produit
- Engagement
- Test
- Assigné 

#### Flèches

Les flèches situées à gauche et à droite de chaque entrée indiquent si ce Test ou cet Engagement en particulier est présent la veille et/ou le lendemain. 

Par exemple, un Test créé le jour même où il est consulté n'aura pas de flèche à gauche, car ce Test n'existait pas la veille. À l'inverse, un Test se terminant le jour où il est consulté n'aura pas de flèche à droite, car l'entrée n'existera pas le lendemain.

Par exemple, comme le dernier Engagement de la capture d'écran ci-dessous (**En cours** Example Product A ▶ **Sample Engagement** (Non assigné)) est consulté le jour de sa création, et que la date de fin cible a été fixée au lendemain, aucune flèche n'apparaît ni à gauche ni à droite.

![image](images/calendar2.png)
