---
title: "Sysdig Secure"
description: "Cómo configurar el Conector Upstream de Sysdig Secure para DefectDojo"
weight: 130
audience: pro
---
El conector de Sysdig Secure importa **hallazgos de vulnerabilidades de contenedores / CNAPP** desde la API de gestión de vulnerabilidades de Sysdig Secure. Sincroniza toda la cuenta en el/los alcance(s) configurado(s) y crea un producto de DefectDojo para cada agrupación de activos escaneados.

#### Prerrequisitos

Un **token de API** de Sysdig Secure: en Sysdig Secure, vaya a **Settings > Sysdig Secure API Token** y copie el token. También necesita la **URL de región** de Sysdig (por ejemplo, `https://us2.app.sysdig.com`, `https://eu1.app.sysdig.com`, o su host on-premises).

#### Asignaciones del conector

1. Introduzca la URL de región/base de Sysdig en el campo **Location**.
2. Introduzca el token de API en el campo **Secret**.
3. Opcionalmente, establezca **Scopes** — una lista separada por comas de `runtime`, `registry`, y/o `pipeline` (déjelo en blanco para `runtime`, el alcance de cargas de trabajo desplegadas).
4. Opcionalmente, establezca **Runtime Product Grouping** — cómo se asignan los resultados de runtime a los productos: `cluster`, `namespace`, `workload`, o `image` (déjelo en blanco para `namespace`). Los resultados de registry y pipeline siempre se agrupan por repositorio de imágenes.
5. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada agrupación de activos se convierte en un Record. Para cada resultado de análisis, el conector importa cada paquete vulnerable como un hallazgo. Los hallazgos de **runtime** (cargas de trabajo desplegadas) se registran como hallazgos dinámicos y se etiquetan con su contexto de clúster/namespace/workload/contenedor de Kubernetes; los hallazgos de **registry** y **pipeline** se registran como hallazgos estáticos de análisis de imágenes. La severidad `NEGLIGIBLE` de Sysdig se asigna a Informativa.
