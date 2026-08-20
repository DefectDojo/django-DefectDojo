---
title: "Veracode"
description: "Cómo configurar el Conector Upstream de Veracode para DefectDojo"
weight: 137
audience: pro
---
El conector de Veracode importa hallazgos de aplicaciones desde la plataforma Veracode, divididos por tipo de análisis en los tipos de hallazgo **SAST**, **DAST**, **SCA** y **Manual**. DefectDojo crea un Record para cada **aplicación** de Veracode.

#### Prerrequisitos

Genere una **credencial de API** de Veracode para una cuenta que pueda ver las aplicaciones que desea importar: en la Veracode Platform, abra el menú de su cuenta > **API Credentials** y seleccione **Generate API Credentials** (consulte [Managing Veracode API credentials](https://docs.veracode.com/r/c_api_credentials3)). Copie tanto el **API ID** como la **API Secret Key** — la clave secreta solo se muestra una vez.

#### Asignaciones del conector

1. Introduzca la URL base de la API de Veracode en el campo **Location**: `https://api.veracode.com` (región comercial), `https://api.veracode.eu` (región europea), o `https://api.veracode.us` (región federal de EE. UU.).
2. Introduzca el API ID en el campo **API ID**.
3. Introduzca la clave secreta de API en el campo **Secret**.
4. Opcionalmente, establezca una **Minimum Severity** para limitar qué hallazgos se importan.

Cada aplicación de Veracode se convierte en un Record. Solo se importan los hallazgos **abiertos**, por lo que una nueva importación cierra los hallazgos que Veracode reporta como resueltos.
