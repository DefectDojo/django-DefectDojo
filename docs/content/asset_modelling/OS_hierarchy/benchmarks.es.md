---
title: Benchmarks de OWASP ASVS
description: Compare un Producto con el OWASP Application Security Verification Standard
  (ASVS).
weight: 6
audience: opensource
---

DefectDojo permite comparar Productos con el [OWASP Application Security Verification Standard (ASVS)](https://owasp.org/www-project-application-security-verification-standard/), que proporciona una base para probar los controles técnicos de seguridad de las aplicaciones web.

Los Benchmarks le permiten medir en qué medida un Producto cumple con los requisitos de seguridad definidos por su organización, y publicar una puntuación en la página del Producto para mayor visibilidad.

## Acceder a los Benchmarks

Los Benchmarks están disponibles desde la página del **Producto**. Para abrir la vista de Benchmarks, seleccione el menú desplegable en la parte superior derecha de la página del Producto y elija **OWASP ASVS v.3.1** cerca de la parte inferior del menú.

## Niveles de Benchmark

OWASP ASVS define tres niveles de cobertura de verificación:

- **Nivel 1** – Para todo el software. Cubre los requisitos de seguridad más críticos con el menor costo de verificación. Este es el nivel predeterminado en DefectDojo.
- **Nivel 2** – Para aplicaciones que contienen datos sensibles. Adecuado para la mayoría de las aplicaciones.
- **Nivel 3** – Para las aplicaciones más críticas, como aquellas que realizan transacciones de alto valor o almacenan datos médicos, financieros o de seguridad sensibles.

Puede alternar entre niveles utilizando el menú desplegable en la parte superior derecha de la vista de Benchmarks.

## Puntuación del Benchmark

El lado izquierdo de la vista de Benchmarks muestra la puntuación actual de su Producto en el nivel de ASVS seleccionado:

- La **puntuación deseada** que su organización ha establecido como objetivo
- El **porcentaje de benchmarks aprobados** para alcanzar dicha puntuación
- El **número total de benchmarks habilitados** para el nivel seleccionado

Al habilitar la casilla **Publicar**, la puntuación de ASVS se mostrará directamente en la página del Producto.

## Gestionar entradas de Benchmark

Las entradas individuales de benchmark pueden marcarse como aprobadas o no aprobadas a medida que su equipo avanza en los controles de ASVS. Se pueden añadir o actualizar entradas de benchmark adicionales, más allá del conjunto predeterminado de ASVS, a través del **sitio de administración de Django**.
