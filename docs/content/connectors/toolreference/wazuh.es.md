---
title: "Wazuh"
description: "Cómo configurar el Conector Upstream de Wazuh para DefectDojo"
weight: 140
audience: pro
---
El conector de Wazuh usa el Wazuh Indexer (OpenSearch) para obtener hallazgos de vulnerabilidades. Wazuh 4.8 y versiones posteriores almacenan los CVE detectados en el Indexer en lugar de en la API del servidor Wazuh, por lo que este conector los lee directamente del índice `wazuh-states-vulnerabilities-*`.

DefectDojo crea un Record para cada agente (endpoint) de Wazuh e importa los CVE detectados de ese agente como hallazgos de forma programada.

#### Prerrequisitos

Necesitará:

* La URL base de su Wazuh Indexer, incluido el puerto (el Indexer escucha por defecto en el puerto 9200). DefectDojo se conecta directamente al Indexer, por lo que este endpoint debe ser accesible desde DefectDojo. Para implementaciones autoadministradas, es el host que ejecuta el Wazuh Indexer. Para Wazuh Cloud, use el endpoint del Indexer que se muestra en su consola de Wazuh Cloud, que es distinto de la URL del panel de Wazuh.
* Un usuario y contraseña del Indexer con acceso de lectura al índice `wazuh-states-vulnerabilities-*`. Recomendamos crear un usuario dedicado para DefectDojo.

La detección de vulnerabilidades debe estar habilitada en Wazuh para que se rellene el índice de estado de vulnerabilidades. Consulte la [documentación de detección de vulnerabilidades de Wazuh](https://documentation.wazuh.com/current/user-manual/capabilities/vulnerability-detection/index.html) para más información.

#### Asignaciones del conector

1. Introduzca la URL base de su Wazuh Indexer en el campo **Location**, incluyendo el esquema y el puerto, por ejemplo `https://your-indexer.example.com:9200`. No incluya una ruta final. DefectDojo construye las rutas de búsqueda automáticamente.
2. Introduzca el nombre de usuario del Indexer en el campo **Username**.
3. Introduzca la contraseña del Indexer en el campo **Password**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importarán.
