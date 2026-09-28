---
title: "Quay"
description: "Cómo configurar el Conector Upstream de Quay para DefectDojo"
weight: 110
audience: pro
---
El conector de Quay usa la API REST de Project Quay para descubrir repositorios de contenedores e importar los informes de vulnerabilidades generados por el escáner **Clair** integrado de Quay. DefectDojo crea un Record para cada **repositorio** de Quay y, en cada Sync, lee el informe de seguridad de Clair del manifiesto de imagen de cada tag activo.

#### Requisitos previos

El escaneo de seguridad (Clair) debe estar habilitado en su instancia de Quay, y necesitará un **token de acceso OAuth 2** de Quay:

* En Quay, cree (o abra) una Organization, vaya a **Applications**, cree una aplicación OAuth y luego **Generate Token** con al menos el alcance (scope) **Read repositories**. Se recomienda una aplicación dedicada para DefectDojo.
* El token se envía como un Bearer token en cada solicitud y nunca se registra en los logs.

#### Asignaciones del conector

1. Ingrese la URL base de Quay en el campo **Location**, por ejemplo `https://quay.io` o su instancia autoalojada `https://quay.example.com`. La URL debe ser HTTPS; no incluya una ruta de API al final: DefectDojo construye las rutas de la API automáticamente.
2. Ingrese el token de acceso OAuth en el campo **Secret**.
3. Opcionalmente, establezca un **Namespace** para restringir el descubrimiento a una única organización o usuario de Quay. Déjelo en blanco para descubrir todos los repositorios que el token pueda leer.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

DefectDojo asigna cada **repositorio** de Quay a un Record. Para cada repositorio, enumera los tags activos, los deduplica a sus manifiestos de imagen únicos (un manifiesto compartido por varios tags se escanea una sola vez) y lee el informe de Clair de cada manifiesto. Los manifiestos que Clair aún no ha terminado de escanear (por ejemplo, una lista de manifiestos multi-arquitectura, o una imagen aún en cola) se omiten hasta un Sync posterior. Cada vulnerabilidad de Clair se convierte en un hallazgo: el paquete afectado es el componente, la versión corregida se convierte en la mitigación, y las severidades **Negligible**/**Unknown** de Clair se registran como **Informativa**.

Consulte la [documentación de la API de Project Quay](https://docs.projectquay.io/api_quay.html) y la [documentación de Clair](https://quay.github.io/clair/) para más información.
