---
title: Calendario
description: Cómo usar el Calendario en DefectDojo Pro
audience: opensource
weight: 9
---

El Calendario de DefectDojo ofrece una vista de línea de tiempo centralizada de todos los Compromisos y Tests con fechas de inicio y fin definidas, lo que permite a los Usuarios comprender rápidamente la actividad de pruebas en todos los Productos, identificar solapamientos de programación y navegar directamente a los objetos relacionados. 

Cuando un Usuario crea un Compromiso o Test y define fechas de inicio y fin, se agrega automáticamente una entrada correspondiente al Calendario. Las entradas aparecen en todas las fechas desde la fecha de inicio definida hasta la fecha de fin definida, inclusive. 

## Acceder al Calendario 

Se puede acceder a la página del Calendario a través del botón Calendario en la barra lateral. 

![imagen](images/OSC_ss3.png)

## Visibilidad y permisos 

### Visibilidad 

La página del Calendario incluye filtros en la parte superior y una cuadrícula mensual del Calendario debajo. Use los controles de navegación encima del Calendario para moverse entre meses. 

La vista mensual se muestra como una cuadrícula fija de seis semanas, comenzando con la semana que contiene el primer día del mes seleccionado.

Las entradas visibles dentro del Calendario se pueden filtrar según el tipo de objeto (Compromisos o Tests) y el Testing Lead, que se establece dentro de la configuración del Compromiso o Test. Después de seleccionar los criterios de filtro, haga clic en Aplicar para actualizar la vista del Calendario.

Solo se puede mostrar un tipo de objeto a la vez. Cambiar entre Compromisos y Tests actualiza la vista del Calendario en consecuencia.

### Permisos 

El Calendario respeta los permisos a nivel de objeto de DefectDojo. Los Usuarios solo ven los Compromisos y Tests a los que están autorizados a acceder.

## Ver e interactuar con las entradas 

Dentro de cada celda de fecha, las entradas se ordenan alfabéticamente según el nombre del objeto. Al hacer clic en una entrada, se redirige al objeto correspondiente.

La cantidad de entradas visibles cada día es dinámica y cambia según el tamaño de pantalla y el nivel de zoom del navegador. Si la cantidad de entradas supera el espacio disponible en una celda de fecha, aparece en la parte inferior de la celda un enlace con el formato “+X more”.

![imagen](images/OSC_ss1.png)

Haga clic en el enlace “+X more” para abrir un modal que muestra todas las entradas de esa fecha. 

![imagen](images/OSC_ss2.png)

Es importante destacar que el Calendario en sí es una vista de solo lectura. Las fechas deben modificarse dentro de la configuración del objeto Compromiso o Test correspondiente. 

### Lógica de nomenclatura 

La nomenclatura de las entradas en el Calendario varía ligeramente según el tipo de objeto. 

Las entradas de Compromiso incluyen: 
- Nombre del Producto
- Nombre del Compromiso
- Testing Lead

Las entradas de Test incluyen:
- Nombre del Producto
- Nombre del Compromiso
- Tipo de Test 
- Testing Lead
