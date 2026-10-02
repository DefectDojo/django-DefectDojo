---
title: Habilitación de la deduplicación
description: Cómo habilitar la deduplicación a nivel de Producto o de Compromiso
weight: 2
audience: pro
aliases:
- /es/en/working_with_findings/finding_deduplication/enabling_product_deduplication
---

La deduplicación puede aplicarse a nivel de todo el Producto, o limitarse de forma más específica a un solo Compromiso.

## Deduplicación para Productos

1. Navegue a la página de configuración del sistema: **Configuración > Sistema > ⚙️ Configuración del sistema** en la barra lateral (**Configuración > Configuración de Pro > Configuración del sistema** en instancias que aún usan el diseño de menú anterior).

![imagen](images/enabling_product-level_deduplication.png)

2. La tarjeta **Configuración de deduplicación y hallazgos** está en la parte superior de la página **Configuración del sistema**.

![imagen](images/enabling_product-level_deduplication_2.png)

### Habilitar la deduplicación de hallazgos

**Habilitar la deduplicación de hallazgos** activa el Algoritmo de deduplicación para todos los Hallazgos. Una vez habilitado, la deduplicación se ejecuta en cada importación posterior: DefectDojo compara los Hallazgos importados con los Hallazgos existentes en el Producto de destino y marca los duplicados según su configuración.

### Eliminar hallazgos duplicados

**Eliminar hallazgos duplicados**, combinado con el campo **Cantidad máxima de duplicados**, limita cuántos Hallazgos duplicados conserva DefectDojo. Cuando está habilitado, un trabajo en segundo plano elimina periódicamente los duplicados excedentes de modo que cada Hallazgo original conserve no más de la cantidad configurada en **Cantidad máxima de duplicados**. Los duplicados más antiguos se eliminan primero.

## Deduplicación para Compromisos

En lugar de deduplicar en todo un Producto, puede limitar la deduplicación a un solo Compromiso.

### Abrir el formulario de Compromiso

* **Para un Compromiso nuevo:** abra el submenú **📥 Compromisos** en la barra lateral y haga clic en **+ Nuevo Compromiso**.

![imagen](images/enabling_deduplication_within_an_engagement.png)

* **Para un Compromiso existente (desde la página Todos los Compromisos):** abra el menú **⋮** del Compromiso y seleccione **Editar Compromiso**.

![imagen](images/enabling_deduplication_within_an_engagement_2.png)

* **Para un Compromiso existente (desde la página del Compromiso):** abra el menú **⚙️ Engranaje** en la esquina superior derecha de la página y seleccione **Editar Compromiso**.

![imagen](images/enabling_deduplication_within_an_engagement_3.png)

### Completar el formulario de Compromiso

1. En el formulario de Compromiso, ubique la casilla ☐ **Aislar la deduplicación de otros Compromisos**. Aparece encima del panel **Campos opcionales +**.
2. Marque la casilla para limitar la deduplicación a este Compromiso.
3. Envíe el formulario.

Cuando esta opción está habilitada, los Hallazgos de este Compromiso solo se deduplicarán contra otros Hallazgos dentro del mismo Compromiso. Los Hallazgos de otros Compromisos en el mismo Producto son ignorados por el Algoritmo de deduplicación.

![imagen](images/enabling_deduplication_within_an_engagement_4.png)
