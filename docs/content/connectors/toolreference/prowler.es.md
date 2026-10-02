---
title: "Prowler"
description: "Cómo configurar el Conector Upstream de Prowler para DefectDojo"
weight: 108
audience: pro
---
El conector de Prowler usa la API REST de **Prowler App** para importar hallazgos de postura de seguridad en la nube (CSPM) desde una instancia de Prowler App autoalojada. DefectDojo descubre cada **provider** (cuenta en la nube) de Prowler como un Record e importa los hallazgos **FAIL** del escaneo completado más reciente de ese provider.

#### Requisitos previos

Necesitará una instancia de **Prowler App** autoalojada en ejecución, y ya sea un correo electrónico y contraseña de usuario (para autenticación JWT) o una **API key** de Prowler App. Los hallazgos solo aparecen una vez que haya conectado una cuenta en la nube (AWS, GCP, Azure, Kubernetes, ...) en Prowler App y ejecutado un escaneo.

#### Asignaciones del conector

1. Ingrese la URL de Prowler App en el campo **Location** (por ejemplo, `https://prowler.your-company.com`).
2. Para autenticación JWT, ingrese el **Email** y **Password** del usuario de Prowler App. Alternativamente, deje esos campos en blanco e ingrese una **API Key** de Prowler App. Si se proporcionan ambos, se usa el email/password (JWT).
3. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan. Los hallazgos por debajo de la severidad seleccionada no se importan.

DefectDojo crea un Record para cada provider de Prowler e importa los hallazgos FAIL de su escaneo completado más reciente, asignando las severidades de Prowler a las severidades de DefectDojo, el recurso en la nube afectado (ARN/resource id) como componente, y la remediación y el riesgo del check al hallazgo. Los hallazgos silenciados (muted) se omiten. La cuenta en la nube, la región y el servicio se adjuntan como etiquetas (tags).

Para más información, consulte la **[documentación de la API de Prowler App](https://api.prowler.com/api/v1/docs)**.
