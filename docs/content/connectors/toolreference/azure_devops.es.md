---
title: "Azure DevOps"
description: "Cómo configurar el Conector Upstream de Azure DevOps para DefectDojo"
weight: 20
audience: pro
---
El conector de Azure DevOps es un **Conector de activos**: enumera los repositorios git de cada proyecto de su organización de Azure DevOps y crea un Activo de DefectDojo para cada repositorio, agrupados en Organizaciones según el proyecto de Azure DevOps. No se importa ningún hallazgo.

#### Prerrequisitos

Necesitará un Personal Access Token (PAT) para la organización. Recomendamos generar el token desde una cuenta de servicio dedicada. Solo se requieren ámbitos de lectura:

1. En Azure DevOps, abra **User settings \> Personal access tokens \> New Token**.
2. Haga clic en **Show all scopes** y, a continuación, seleccione **Code: Read** y **Project and Team: Read**.

Solo se admite Azure DevOps Services (dev.azure.com); actualmente no se admite Azure DevOps Server on-premise.

#### Asignaciones del conector

1. Ingrese la URL de su organización en el campo **Location**: `https://dev.azure.com/{your-organization}`. También se aceptan las URL heredadas `https://{your-organization}.visualstudio.com`, y cualquier segmento de ruta adicional (por ejemplo, un enlace a un proyecto específico) se ignora.
2. Ingrese el PAT en el campo **Secret**.

Cada repositorio se convierte en un Registro con el nombre del repositorio, agrupado por su **proyecto** de Azure DevOps. Los repositorios deshabilitados se omiten, por lo que deshabilitar o eliminar un repositorio marca su Registro como `MISSING` en la siguiente Sync.
