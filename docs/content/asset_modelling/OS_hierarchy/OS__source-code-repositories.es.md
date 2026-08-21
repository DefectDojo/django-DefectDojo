---
title: Vincular Hallazgos al código fuente
description: Integración de repositorios para navegar hasta la ubicación de los hallazgos
  en el código fuente.
draft: false
weight: 5
audience: opensource
aliases:
- /es/en/working_with_findings/organizing_engagements_tests/source-code-repositories
---

Ciertas herramientas (particularmente las herramientas SAST) incluirán el nombre de archivo asociado y el número de línea en los datos de la vulnerabilidad. Si el repositorio del código fuente está especificado en el Compromiso, DefectDojo presentará la ruta del archivo como un enlace y el usuario podrá navegar directamente hasta la ubicación de la vulnerabilidad.

## Configurar el repositorio en el Compromiso y el Test

### Compromiso

Al editar el Compromiso, los usuarios pueden establecer la URL del repositorio específico de gestión de código fuente.  **(En la interfaz de Pro, este campo se puede configurar en Editar Compromiso > Campos opcionales > Repo)**.

Para un Compromiso Interactivo, debe ser una URL que especifique la rama:
- para GitHub - como https://github.com/DefectDojo/django-DefectDojo/tree/dev
![Editar Compromiso (GitHub)](images/source-code-repositories_1.png)
- para GitLab - como https://gitlab.com/gitlab-org/gitlab/-/tree/master
![Editar Compromiso (Gitlab)](images/source-code-repositories-gitlab_1.png)
- para BitBucket público - como    (como una URL de git clone)
![Editar Compromiso (Bitbucket público)](images/source-code-repositories-bitbucket_1.png)
- para BitBucket independiente/on-premise https://bb.example.com/scm/some-project/some-repo.git o https://bb.example.com/scm/some-user-name/some-repo.git para un repositorio público de usuario (como una URL de git clone)
![Editar Compromiso (Bitbucket independiente)](images/source-code-repositories-bitbucket-onpremise_1.png)

Para Compromisos de CI/CD, el hash de commit, la rama/tag y la línea de código pueden variar, por lo que solo es necesario incluir la URL del repositorio.
- para GitHub - como `https://github.com/DefectDojo/django-DefectDojo`
- para GitLab - como `https://gitlab.com/gitlab-org/gitlab`
- para BitBucket público, Gitea y Codeberg - como `https://bitbucket.org/some-user/some-project.git` (como una URL de git clone)
- para BitBucket independiente/on-premise `https://bb.example.com/scm/some-project.git` o `https://bb.example.com/scm/some-user-name/some-repo.git` para un repositorio público de usuario (como una URL de git clone)

En un Compromiso de CI/CD, puede especificar un hash de commit o una rama/tag en el formulario **Editar Compromiso**, que se añadirá a los enlaces generados por DefectDojo.  Si estos no se configuran, la URL del SCM deberá contener un enlace completo que incluya la rama del código.

La URL de navegación del SCM se compone a partir de la URL del repositorio utilizando el tipo de SCM. Se puede establecer un tipo de SCM específico en el campo personalizado del Activo "scm-type". Si no se establece ningún "scm-type" y la URL contiene "https://github.com", se asume un tipo de SCM "github".

Campos personalizados del Activo:

![Campos personalizados del Activo](images/asset-custom-fields_1.png)

Agregar tipo de SCM del Activo:

![Tipo de SCM del Activo](images/asset-scm-type_1.png)

Los tipos de SCM posibles pueden ser 'github', 'gitlab', 'bitbucket', 'bitbucket-standalone', 'gitea', 'codeberg' o ninguno (para GitHub por defecto).


## Enlaces al código fuente en los Hallazgos

Al visualizar un hallazgo, la ubicación se presentará como un enlace, si el repositorio del código fuente se ha establecido en el Compromiso:

![Enlace a la ubicación](images/source-code-repositories_2.png)

Al hacer clic en este enlace se abrirá una nueva pestaña en el navegador, con el archivo fuente de la vulnerabilidad en el número de línea correspondiente:

![Ver en el repositorio](images/source-code-repositories_3.png)
