---
title: "Dependency-Track"
description: "Cómo configurar el Conector Upstream de Dependency-Track para DefectDojo"
weight: 48
audience: pro
---
Este conector obtiene datos de una instancia on\-premise de Dependency\-Track mediante la API REST.

​**Asignaciones del conector**

1. Introduzca la URL de su servidor local de Dependency\-Track en el campo **Location**.
2. Introduzca una clave de API válida en el campo **Secret**.

Para generar una clave de API de Dependency\-Track:

1. **Access Management**: navegue hasta Administration \> Access Management \> Teams en la interfaz de Dependency\-Track.
2. **Teams Setup**: puede crear un nuevo equipo o seleccionar uno existente. Los equipos permiten gestionar el acceso a la API según la pertenencia al grupo.
3. **Generate API Key**: en la página de detalles del equipo seleccionado, busque la sección "API Keys". Haga clic en el botón \+ para generar una nueva clave de API.
4. **Assign Permissions**: en la sección "Permissions" de la página del equipo, haga clic en el botón \+ para abrir el selector de permisos. Elija los permisos **VIEW\_PORTFOLIO** y **VIEW\_VULNERABILITY** para habilitar el acceso mediante API a los portafolios de proyectos y a los detalles de vulnerabilidades.
5. Haga clic en "**Select**" para confirmar y guardar estos permisos.

Para obtener más información, consulte la **[documentación de Dependency\-Track](https://docs.dependencytrack.org/integrations/rest-api/)**.
