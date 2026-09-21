---
title: "Have I Been Pwned"
description: "Cómo configurar el Conector Upstream de Have I Been Pwned para DefectDojo"
weight: 72
audience: pro
---
El conector Have I Been Pwned (HIBP) usa la API REST de HIBP para informar de qué cuentas de los dominios propios de su organización han aparecido en filtraciones de datos conocidas. DefectDojo detecta cada dominio que haya verificado con HIBP e importa un hallazgo por cada filtración que afecte a ese dominio.

#### Requisitos previos

Necesitará una clave de API de Have I Been Pwned con búsqueda de dominio, lo que requiere un nivel de suscripción **Core** o superior. Puede obtener una clave desde su [cuenta de Have I Been Pwned](https://haveibeenpwned.com/API/Key).

También debe **verificar al menos un dominio** en su cuenta de HIBP antes de que haya datos de filtraciones disponibles. HIBP permite verificar un dominio mediante registro TXT de DNS, metaetiqueta, carga de archivo o correo electrónico, en **Domain search** dentro de su cuenta. Hasta que un dominio esté verificado, el conector no detecta ningún dominio y no importa ningún hallazgo.

#### Asignaciones del conector

1. Introduzca `https://haveibeenpwned.com` en el campo **Location**.
2. Introduzca su clave de API en el campo **Secret**.
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.

DefectDojo crea un Registro independiente para cada dominio que haya verificado con HIBP, e importa un hallazgo por cada filtración que afecte a las cuentas de ese dominio. La severidad de cada hallazgo refleja el tipo de datos que expuso la filtración, y su descripción enumera las cuentas afectadas de su dominio para que su equipo pueda actuar sobre ellas.

Consulte la [documentación de la API de Have I Been Pwned](https://haveibeenpwned.com/API/v3) para obtener más información.
