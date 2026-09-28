---
title: Calendario
description: Cómo usar el Calendario en DefectDojo Pro
audience: pro
weight: 9
---

DefectDojo incluye un Calendario integrado para que pueda hacer seguimiento de todos los Compromisos y Tests anteriores y activos dentro de su organización. Cada vez que un Usuario crea un nuevo Compromiso o Test y establece las fechas de inicio y fin, se agregará automáticamente una entrada correspondiente al Calendario. 

### Página de inicio 

La página del Calendario incluye filtros en la parte superior y un calendario mensual debajo. Los filtros pueden ajustar qué resultados aparecen en el calendario según:
- Compromiso y/o Test 
- Fecha de inicio y fin 
- Estado del Compromiso (por ejemplo, Completado, En curso, En espera, etc.) 
- Responsable del Compromiso/Test (es decir, ¿a quién está asignado el Compromiso/Test?) 
- Tipo de Compromiso (por ejemplo, Interactivo o CI/CD)
- Tipo de Test (por ejemplo, Pen Test, Acunetix Scan, Tenable Scan, etc.) 

![image](images/calendar1.png)
 
Una vez filtrados, los resultados se pueden exportar y compartir como un archivo ICS. 

Es importante destacar que el Calendario solo mostrará los Compromisos y Tests a los que tenga acceso el Usuario que está viendo el calendario. No mostrará los Compromisos y Tests que el Usuario no tenga permiso para ver. 

## Funcionalidades 

### Vista mensual

El calendario mensual mostrará una vista previa de cinco entradas por día. Las entradas adicionales que ocurran ese día quedarán ocultas a menos que se haga clic en **"+ [X] events"** dentro de la celda de una fecha determinada. Al hacer clic, el calendario pasará de una vista mensual a una vista diaria.

Al hacer clic en una entrada de un Test o Compromiso, se abrirá una ventana modal con información adicional sobre esa entrada, entre ellas: 
- Fecha de inicio y fin 
- Tipo de Test o Compromiso 
- Responsable 
- Estado 
- Activo 
- Compromiso 
- Test 

Desde allí, se puede acceder al Activo, Compromiso o Test mediante un hipervínculo.

### Vista diaria 

En la vista diaria, todos los Compromisos y Tests actualmente activos aparecerán en orden cronológico descendente (es decir, un Compromiso o Test recién creado se ubicará en la parte inferior de la entrada de ese día). Los Compromisos aparecen en azul, mientras que los Tests aparecen en naranja.

Si se configura dentro del Compromiso/Test correspondiente, el título de cada entrada en el calendario diario incluirá lo siguiente:
- Estado 
- Producto
- Compromiso
- Test
- Asignado 

#### Flechas

Las flechas a la izquierda y a la derecha de cada entrada indican si ese Test o Compromiso en particular está presente el día anterior y/o el día siguiente. 

Por ejemplo, un Test que se creó el mismo día en que se está visualizando no tendrá flechas a la izquierda porque ese Test no existía el día anterior. Por el contrario, un Test que finaliza el mismo día en que se está visualizando no tendrá flechas a la derecha porque la entrada no existirá al día siguiente.

Por ejemplo, dado que el último Compromiso en la captura de pantalla a continuación (**In Progress** Example Product A ▶ **Sample Engagement** (Unassigned)) se está visualizando el día en que fue creado, y la Fecha de finalización prevista se estableció para el día siguiente, no aparecen flechas ni a la izquierda ni a la derecha.

![image](images/calendar2.png)
