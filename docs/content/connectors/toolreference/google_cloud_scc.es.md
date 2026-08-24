---
title: "Google Cloud Security Command Center"
description: "Cómo configurar el Conector Upstream de Google Cloud Security Command Center para DefectDojo"
weight: 67
audience: pro
---
El conector de Google Cloud SCC utiliza la API REST v2 de Security Command Center para importar los hallazgos de seguridad activos de su organización, carpeta o proyecto de Google Cloud. DefectDojo crea un Registro para cada **proyecto** de Google Cloud que tenga hallazgos abiertos.

#### Requisitos previos

Security Command Center debe estar **activado** en su organización (el nivel Standard es gratuito). A continuación, necesitará una cuenta de servicio que pueda listar hallazgos, y una clave JSON para ella:

1. En Google Cloud, cree una cuenta de servicio; se recomienda una dedicada para DefectDojo.
2. Otórguele el rol **Security Center Findings Viewer** (`roles/securitycenter.findingsViewer`) en el alcance que desea importar (organización, carpeta o proyecto).
3. Cree una **clave JSON** para la cuenta de servicio y descárguela.

#### Asignaciones del conector

1. Deje el campo **Location** con el valor predeterminado `https://securitycenter.googleapis.com`, salvo que utilice un endpoint no estándar.
2. En el campo **Parent Resource**, introduzca el alcance desde el que importar: `organizations/{id}`, `folders/{id}` o `projects/{id}`.
3. Pegue el contenido completo del archivo de **clave JSON** de la cuenta de servicio en el campo **Service Account Key**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

Solo se importan los hallazgos `ACTIVE` y no silenciados, por lo que los hallazgos que desactive o silencie en SCC se mitigan automáticamente en DefectDojo en la siguiente sincronización. El proyecto de GCP afectado de cada hallazgo se convierte en su Registro.
