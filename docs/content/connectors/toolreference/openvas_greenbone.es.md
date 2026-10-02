---
title: "OpenVAS / Greenbone"
description: "Cómo configurar el Conector Upstream de OpenVAS / Greenbone para DefectDojo"
weight: 98
audience: pro
---
El conector de OpenVAS / Greenbone importa **hallazgos de vulnerabilidades de red** desde una instancia de Greenbone (Greenbone Community Edition o Greenbone Enterprise). Se comunica con `gvmd` mediante **GMP (Greenbone Management Protocol)** —un protocolo XML sobre un socket TLS, no HTTP— y sincroniza toda la instancia: enumera las **tareas (tasks)** de escaneo y crea un producto de DefectDojo para cada una, importando los resultados del informe más reciente de cada tarea.

#### Requisitos previos

Un **usuario GMP** de Greenbone (nombre de usuario + contraseña) y acceso de red al puerto TLS de GMP de gvmd (por defecto **9390**). El stack de compose de Greenbone Community Edition expone gvmd a través de un socket unix, así que para alcanzarlo desde un conector conectado en red debe ejecutar el conector donde pueda acceder al socket, o exponer el puerto TLS de GMP (por ejemplo, un puente TLS con `socat` hacia `gvmd.sock`).

#### Asignaciones del conector

1. Ingrese el host de gvmd en el campo **Location** (host o `host:port`).
2. Ingrese el **Username** y **Password** de GMP.
3. Opcionalmente, establezca el **GMP Port** (por defecto 9390).
4. Para el certificado autofirmado predeterminado de gvmd, proporcione un **CA Certificate (PEM)** contra el cual verificar, o bien establezca **Skip TLS Verification** en `true`.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada tarea de Greenbone se convierte en un Record. Los hallazgos provienen del informe finalizado más reciente de la tarea, uno por cada `<result>`. La severidad se toma del nivel de amenaza (threat level) del resultado (los niveles informativos `Log`/`Debug` de Greenbone se asignan a Informativa), y se registra la puntuación CVSS numérica; las referencias CVE se convierten en identificadores de vulnerabilidad, la solución del NVT se convierte en la mitigación, y el host/puerto de cada resultado se convierte en un endpoint.
