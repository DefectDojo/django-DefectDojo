---
title: "Harbor"
description: "Cómo configurar el Conector Upstream de Harbor para DefectDojo"
weight: 71
audience: pro
---
El conector Harbor usa la API REST v2.0 de Harbor para importar vulnerabilidades de imágenes de contenedor de todo su registro. DefectDojo enumera cada **proyecto** de Harbor y crea un Registro para cada uno, luego recorre los repositorios y artefactos del proyecto e importa las vulnerabilidades de cada artefacto **escaneado** — incorporando la imagen (repositorio + etiqueta/digest) como contexto del hallazgo. No existe configuración por imagen.

#### Requisitos previos

Necesitará una cuenta de Harbor (o una **cuenta robot**) con acceso de extracción/lectura a los proyectos que desea importar. Recomendamos una cuenta robot dedicada: en Harbor, abra un proyecto (o **Administration > Robot Accounts** para un robot de sistema), cree un robot con el permiso **pull** sobre repositorios y artefactos, y copie su nombre completo y su secreto. Los nombres de robot comienzan con `robot$` de forma predeterminada, pero el prefijo es configurable por instancia de Harbor (algunas usan `robot_`) — copie el nombre exactamente como lo muestra Harbor. Un nombre de usuario y contraseña normales también funcionan.

#### Asignaciones del conector

1. Introduzca su URL de Harbor en el campo **Location** — por ejemplo `https://harbor.example.com`. DefectDojo añade automáticamente la ruta de la API `/api/v2.0`.
2. Introduzca el nombre de usuario de Harbor, o el nombre de una cuenta robot exactamente como lo muestra Harbor (`robot$<name>` de forma predeterminada), en el campo **Username**.
3. Introduzca la contraseña o el secreto de la cuenta robot en el campo **Secret**. Se envía mediante autenticación HTTP Basic.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada proyecto de Harbor se convierte en un Registro. Para cada artefacto que tenga un escaneo completado, sus vulnerabilidades se importan como hallazgos; se incluyen el paquete/versión afectados, una severidad derivada de CVSS, el CVE, el CWE y una corrección (versión reparada) cuando Harbor los proporciona. Solo se importan los artefactos escaneados — active un escaneo en Harbor para las imágenes que aún no se hayan escaneado.
