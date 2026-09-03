---
title: "Mend"
description: "Cómo configurar el Conector Upstream de Mend para DefectDojo"
weight: 88
audience: pro
---
El conector Mend (anteriormente **WhiteSource**) usa la API de Mend para importar hallazgos de seguridad de su organización de Mend. DefectDojo crea un Registro para cada **proyecto** de Mend.

#### Requisitos previos

Necesitará un usuario (de servicio) de Mend con una **User Key** (un token de acceso personal) y su **Organization UUID** de Mend. Recomendamos una cuenta de servicio dedicada para que la actividad automatizada sea fácil de distinguir de las acciones manuales del equipo. Encuentre el Organization UUID en la aplicación Mend en **Administration > Organization UUID**.

#### Asignaciones del conector

1. Introduzca la URL de la API de Mend en el campo **Location**. Esta URL es **específica de la región** — use la URL base de la API de la región donde está alojada su organización de Mend.
2. Introduzca el correo electrónico de inicio de sesión del usuario de Mend en el campo **Email**.
3. Introduzca su **Organization UUID** de Mend en el campo **Organization UUID**.
4. Introduzca la **User Key** de Mend en el campo **User Key**.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.
