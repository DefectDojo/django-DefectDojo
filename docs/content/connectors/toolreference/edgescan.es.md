---
title: "Edgescan"
description: "Cómo configurar el Conector Upstream de Edgescan para DefectDojo"
weight: 52
audience: pro
---
El conector de Edgescan utiliza la API REST de Edgescan para importar las vulnerabilidades abiertas de toda su cuenta de Edgescan. DefectDojo enumera todos los **activos** de Edgescan y crea un Registro para cada uno; a continuación, importa las vulnerabilidades abiertas de ese activo como hallazgos. No existe configuración por activo.

#### Requisitos previos

Necesitará un token de API de Edgescan. Créelo desde su cuenta de Edgescan en **Account settings \> API tokens**: introduzca una etiqueta, haga clic en **Create** y copie el token generado (solo se muestra una vez). Recomendamos una cuenta dedicada para el conector, de modo que la actividad automatizada se distinga fácilmente.

#### Asignaciones del conector

1. Introduzca su URL de Edgescan en el campo **Location**: `https://live.edgescan.com` para la plataforma alojada estándar, o el host de su tenant si es distinto.
2. Introduzca su token de API de Edgescan en el campo **Secret**. Se envía en el encabezado `X-API-TOKEN`.
3. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Cada activo de Edgescan se convierte en un Registro, y cada vulnerabilidad abierta de ese activo se importa como un hallazgo. La severidad se asigna desde la escala numérica de Edgescan (1–5) a la escala Informativa–Crítica de DefectDojo, e incluye las referencias CVE, el CWE y un vector CVSS v3 cuando Edgescan los proporciona.
