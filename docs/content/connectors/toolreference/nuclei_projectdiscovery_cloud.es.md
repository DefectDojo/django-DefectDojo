---
title: "Nuclei (ProjectDiscovery Cloud)"
description: "Cómo configurar el Conector Upstream de Nuclei (ProjectDiscovery Cloud) para DefectDojo"
weight: 97
audience: pro
---
El conector de Nuclei usa la API REST de ProjectDiscovery Cloud Platform (PDCP) para obtener resultados de escaneo de [nuclei](https://github.com/projectdiscovery/nuclei) desde su cuenta de PDCP. DefectDojo descubre cada escaneo de la cuenta y crea un Record independiente para cada **escaneo**.

#### Requisitos previos

Necesitará una **API key** de ProjectDiscovery Cloud. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada se distinga claramente de las acciones manuales del equipo. Genere una clave desde **Settings > API Key** en la interfaz de ProjectDiscovery Cloud ([cloud.projectdiscovery.io](https://cloud.projectdiscovery.io)). Los resultados llegan a PDCP ya sea desde escaneos alojados (hosted) o desde la CLI de nuclei ejecutada con `-dashboard`.

#### Asignaciones del conector

1. Ingrese la URL base de la API de PDCP en el campo **Location**: `https://api.projectdiscovery.io`.
2. Ingrese su **API key** en el campo **Secret**.
3. Opcionalmente, ingrese un **Team ID** para limitar la sincronización a un espacio de trabajo de equipo (se encuentra en **Settings > Team**). Si se deja en blanco, DefectDojo sincroniza su espacio de trabajo personal.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **escaneo** de PDCP como un Record independiente e importa los hallazgos de ese escaneo en todas las severidades, incluida la informativa.
