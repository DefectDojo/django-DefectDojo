---
title: "Microsoft Defender for Cloud"
description: "Cómo configurar el Conector Upstream de Microsoft Defender for Cloud para DefectDojo"
weight: 90
audience: pro
---
El conector de Microsoft Defender for Cloud importa hallazgos de vulnerabilidades de **Microsoft Defender Vulnerability Management (MDVM)** tal como los expone Defender for Cloud, tanto hallazgos de **servidor** (CVEs del sistema operativo y del software instalado en VM de Azure) como hallazgos de **registro de contenedores** (CVEs de imágenes de contenedor), incluyendo severidad, puntuación CVSS, el paquete o la imagen afectados y la remediación. DefectDojo descubre las **suscripciones** de Azure que su entidad de servicio (service principal) puede leer y crea un Record por cada suscripción habilitada.

**Tenga en cuenta:** este conector es distinto del conector **Microsoft Defender**, que importa hallazgos de dispositivos desde la API de Defender for Endpoint. Defender for Cloud es un producto de Azure con una superficie de API diferente (Azure Resource Manager / Resource Graph) y un modelo de permisos diferente (Azure RBAC). Ejecute el que corresponda según dónde residan sus hallazgos, o ambos si usa los dos productos.

#### Requisitos previos

Necesita una o más **suscripciones de Azure con Microsoft Defender for Cloud habilitado**, con los planes de Defender pertinentes activados para los recursos que desea escanear (en **Microsoft Defender for Cloud > Environment settings**, y luego seleccione su suscripción):

* **Defender for Servers (Plan 2)**: hallazgos de CVE del sistema operativo y del software de VM de Azure (escaneo de vulnerabilidades sin agente).
* **Defender for Containers**: hallazgos de CVE de imágenes del registro de contenedores.

Los hallazgos de evaluación de vulnerabilidades de SQL y de configuración/postura **no** se importan intencionalmente: este conector solo importa vulnerabilidades CVE.

El conector se autentica como un **registro de aplicación (app registration)** de Microsoft Entra ID mediante el flujo de credenciales de cliente:

1. En el [portal de Azure](https://portal.azure.com), abra **App registrations > New registration**. Asígnele un nombre (por ejemplo, `defectdojo-connector`), deje los valores predeterminados y seleccione **Register**.
2. En la página **Overview** de la aplicación, anote el **Application (client) ID** y el **Directory (tenant) ID**.
3. Abra **Certificates & secrets > New client secret**, establezca una fecha de caducidad y copie el **Value** del secreto de inmediato (solo se muestra una vez). El conector deja de funcionar cuando el secreto caduca, así que anote la fecha.
4. Otorgue a la aplicación acceso de lectura a cada suscripción que desee importar: abra **Subscriptions**, seleccione su suscripción y luego **Access control (IAM) > Add > Add role assignment**. Seleccione el rol **Security Reader** (o **Reader**) y, en la pestaña **Members**, asígnelo a la aplicación que creó; búsquela por el **nombre** o el **object ID** de la aplicación, ya que el selector no coincide con el client ID. Repita esto para cada suscripción.

A diferencia del conector Microsoft Defender basado en dispositivos, no se requieren permisos de API ni consentimiento de administrador: el acceso a Defender for Cloud se rige completamente por la asignación de rol de Azure RBAC descrita arriba.

#### Asignaciones del conector

1. Ingrese `https://management.azure.com` en el campo **Location**. (Para nubes soberanas, use el endpoint de ARM correspondiente, por ejemplo `https://management.usgovcloudapi.net`.)
2. Ingrese el **Directory (tenant) ID** en el campo **Tenant ID**.
3. Ingrese el **Application (client) ID** en el campo **Client ID**.
4. Ingrese el valor del secreto de cliente en el campo **Client Secret**.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada suscripción de Azure habilitada se convierte en un Record. Los hallazgos se leen a través de Azure Resource Graph, por lo que aparecen con rapidez una vez que Defender for Cloud ha escaneado sus recursos, pero los escaneos en sí se ejecutan según la programación de Microsoft: las imágenes del registro de contenedores suelen escanearse dentro de la hora siguiente a su carga (push), mientras que el primer escaneo de vulnerabilidades sin agente de una VM puede tardar varias horas. Es normal que una suscripción recién habilitada sincronice (Sync) cero hallazgos hasta que se hayan escaneado sus recursos.
