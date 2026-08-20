---
title: "Cobalt.io"
description: "Cómo configurar el Conector Upstream de Cobalt.io para DefectDojo"
weight: 37
audience: pro
---
El conector de Cobalt.io utiliza la API de Cobalt.io (v2) para extraer los hallazgos de pentest de su organización de Cobalt.io. DefectDojo detecta todas las organizaciones a las que su token de API tiene acceso y crea un Registro independiente para cada **activo** (la unidad que Cobalt somete a pentest).

#### Requisitos previos

Necesitará un **token de API personal** de Cobalt.io. Recomendamos crear una cuenta de servicio dedicada para DefectDojo, de modo que la actividad automatizada se distinga claramente de las acciones manuales del equipo. Genere un token desde **Settings \> API Tokens** en la interfaz de Cobalt.io. Los tokens de organización se detectan automáticamente \- no es necesario proporcionarlos.

#### Asignaciones del conector

1. Introduzca la URL base de la API de Cobalt.io en el campo **Location**: `https://api.cobalt.io` (o el host de su región, por ejemplo `https://api.us.cobalt.io`).
2. Introduzca su **token de API personal** en el campo **Secret**.
3. De forma opcional, introduzca un **Organization Token** para fijar la sincronización a una sola organización. Si se deja en blanco, DefectDojo sincroniza todas las organizaciones a las que el token de API personal tiene acceso.

DefectDojo asigna cada **activo** de Cobalt.io como un Registro independiente. Los hallazgos se importan para cada activo asignado, y su estado en Cobalt.io (por ejemplo, `valid_fix`, `wont_fix`, `invalid`) determina el estado del hallazgo en DefectDojo.
