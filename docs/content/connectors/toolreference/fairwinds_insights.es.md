---
title: "Fairwinds Insights"
description: "Cómo configurar el Conector Upstream de Fairwinds Insights para DefectDojo"
weight: 56
audience: pro
---
El conector de Fairwinds Insights utiliza la API REST de [Fairwinds Insights](https://insights.fairwinds.com) para importar **hallazgos de seguridad de Kubernetes** de toda su organización. DefectDojo enumera todos los **clusters** activos y crea un Registro para cada uno; a continuación, importa como hallazgos los **action items** de seguridad de ese cluster \(de Polaris, Trivy, Kube\-bench, OPA y los demás informes de Insights\). No existe configuración por cluster.

#### Requisitos previos

Necesitará un nombre de **organización** de Fairwinds Insights y un **API token**. Cree el token en la aplicación de Insights en **Organization Settings \> Tokens**; basta con un token `read_only`. El token tiene alcance de organización y se envía como bearer token; nunca se registra en los logs.

#### Asignaciones del conector

1. Conserve el valor ya rellenado en **Location**, `https://insights.fairwinds.com`, o introduzca explícitamente el host de Insights.
2. Introduzca el nombre de **Organization** de Insights (el slug que aparece en la URL de su panel).
3. Introduzca el token de API de Insights en el campo **Secret**.
4. De forma opcional, defina una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **cluster** activo a un Registro y cada **action item** de Security a un hallazgo: la severidad proviene de la puntuación numérica de Fairwinds \(asignada a la escala Informativa–Crítica de DefectDojo\), el informe de Fairwinds que generó el elemento \(`polaris`, `trivy`, `kube-bench`, ...\) se convierte en una etiqueta de herramienta, se incluyen el recurso de Kubernetes afectado y la imagen del contenedor, y se extraen los identificadores CVE si los hay. Los hallazgos se registran como hallazgos estáticos y se deduplican según el id del action item de Fairwinds.

Consulte la [documentación de la API de Fairwinds Insights](https://insights.docs.fairwinds.com/technical-details/api/) para obtener más información.
