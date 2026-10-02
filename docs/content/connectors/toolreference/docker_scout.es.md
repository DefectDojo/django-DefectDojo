---
title: "Docker Scout"
description: "Cómo configurar el Conector Upstream de Docker Scout para DefectDojo"
weight: 50
audience: pro
---
El conector de Docker Scout utiliza la API del exportador de métricas de Docker Scout para informar sobre la postura de vulnerabilidades de las imágenes de su organización. DefectDojo detecta cada stream de Docker Scout (sus entornos de ejecución) e importa un resumen de las vulnerabilidades y el cumplimiento de políticas de cada uno.

#### Requisitos previos

Necesitará un personal access token de Docker creado por un **owner** de una organización de Docker que esté **inscrita en Docker Scout**. El exportador de métricas es una función a nivel de organización, por lo que una cuenta personal, o una organización no inscrita en Docker Scout, no devolverá datos.

Cree el token desde la configuración de su cuenta de Docker, en **Personal access tokens**, y anote el **organization namespace** de Docker, que también necesitará.

#### Asignaciones del conector

1. Introduzca `https://api.scout.docker.com` en el campo **Location**.
2. Introduzca su personal access token de Docker en el campo **Secret**.
3. Introduzca su namespace de **Organization** de Docker.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

DefectDojo crea un Registro independiente para cada stream de Docker Scout, e importa un hallazgo por severidad para las vulnerabilidades que Docker Scout contabiliza en ese stream, además de un hallazgo por cada imagen que incumple su política de Docker Scout. La API de métricas de Docker Scout informa recuentos agregados en lugar de CVE individuales, por lo que estos hallazgos resumen la postura de un stream. Abra el stream en Docker Scout para ver el detalle por imagen y por CVE.

Consulte la [documentación de Docker Scout](https://docs.docker.com/scout/) para obtener más información.
