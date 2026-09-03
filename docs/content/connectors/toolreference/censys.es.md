---
title: "Censys"
description: "Cómo configurar el Conector Upstream de Censys para DefectDojo"
weight: 32
audience: pro
---
El conector de Censys lee activos de tipo host desde Censys Platform e importa los servicios expuestos de cada host como hallazgos. Usa la API de búsqueda global de Censys Platform para enumerar los hosts a los que lo delimite.

#### Prerrequisitos

Necesitará una cuenta de Censys **Platform** con acceso a la API:

* Un **Personal Access Token**, creado en Censys Platform Console, en Personal Access Tokens.
* Su **Organization ID**, que se muestra en la misma página de configuración bajo "Current Organization". El acceso de la API al endpoint de búsqueda requiere una organización, por lo que se necesita un plan Starter o superior. Los tokens del plan gratuito no tienen Organization ID y no pueden usar la API de búsqueda.

Los datos de CVE y riesgo por host solo están disponibles en los planes Censys Core (enterprise), por lo que en planes inferiores los hallazgos representan servicios expuestos en lugar de vulnerabilidades.

Consulte la [documentación de la API de Censys Platform](https://docs.censys.com/reference/get-started) para obtener más información.

#### Asignaciones del conector

1. Ingrese `https://api.platform.censys.io` en el campo **Location**.
2. Ingrese su Personal Access Token en el campo **API Key**.
3. Ingrese su **Organization ID**.
4. Ingrese una **Search Query** que delimite la importación a sus propios activos, por ejemplo `host.autonomous_system.asn: <your ASN>` o `host.ip: 203.0.113.0/24`.
5. Opcionalmente, configure una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo crea un Registro para cada host e importa sus servicios expuestos como hallazgos.
