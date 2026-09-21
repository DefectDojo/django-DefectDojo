---
title: "Sonatype IQ"
description: "Cómo configurar el Conector Upstream de Sonatype IQ para DefectDojo"
weight: 128
audience: pro
---
El conector de Sonatype IQ usa la API REST del servidor Sonatype IQ (Nexus Lifecycle) para importar vulnerabilidades de componentes de código abierto. Enumera todas las aplicaciones de su organización de IQ y, para cada una, importa las vulnerabilidades de componentes del informe más reciente de esa aplicación en la etapa del ciclo de vida que configure. DefectDojo crea un Record para cada aplicación automáticamente — no hay configuración por aplicación.

#### Prerrequisitos

Necesitará una cuenta de usuario de Sonatype IQ con el permiso **View IQ Elements** en las aplicaciones que desea importar. Sonatype recomienda autenticarse con un **user token** (generado en **My Profile > User Token** en IQ Server) en lugar de una contraseña; las dos partes del token se corresponden con los campos Username y User Token que aparecen a continuación. El conector funciona tanto con instancias de IQ Server autoalojadas como con instancias alojadas por Sonatype (SaaS).

#### Asignaciones del conector

1. En el campo **Location**, introduzca la URL base de su IQ Server — para un servidor autoalojado, `https://iq.example.com`; para una instancia alojada por Sonatype, `https://<tenant>.sonatype.app/platform`.
2. Introduzca el usuario de IQ (o la parte de código de usuario de su user token) en el campo **Username**.
3. Introduzca el user token de IQ (o la contraseña) en el campo **User Token**.
4. Opcionalmente, establezca un **Stage** para elegir de qué etapa del ciclo de vida se importa el informe por aplicación (`build`, `stage-release`, `release`, etc.). Déjelo en blanco para usar `build`.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada aplicación se convierte en un Record, y cada problema de seguridad en el informe más reciente de esa aplicación para la etapa seleccionada se importa como un hallazgo. La severidad se deriva de la puntuación numérica del problema, y se incluyen las referencias CVE, el CWE, el vector CVSS y la URL del paquete (PURL) del componente afectado cuando están disponibles.
