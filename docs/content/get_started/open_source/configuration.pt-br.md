---
title: Configuração
description: O DefectDojo é altamente configurável.
draft: false
weight: 2
audience: opensource
aliases:
- /pt-br/en/open_source/installation/configuration
---

## dojo/settings/settings.dist.py

As configurações principais são armazenadas em [`dojo/settings/settings.dist.py`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/settings.dist.py). É ótimo usar este arquivo como referência para o que pode ser configurado, mas ele não deve ser editado diretamente, pois as alterações serão sobrescritas ao atualizar o DefectDojo. Existem vários métodos para alterar as configurações padrão:

### Variáveis de ambiente

A maioria dos parâmetros pode ser definida por variáveis de ambiente.

Ao implantar o DefectDojo via **Docker Compose**, você pode definir variáveis de ambiente em [`docker-compose.yml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/docker-compose.yml). Esteja ciente de que você precisa definir as variáveis para três serviços: `uwsgi`, `celerybeat` e `celeryworker`.

Ao implantar o DefectDojo em um cluster **Kubernetes**, você pode definir variáveis de ambiente como `extraConfigs` e `extraSecrets` em [`helm/defectdojo/values.yaml`](https://github.com/DefectDojo/django-DefectDojo/blob/master/helm/defectdojo/values.yaml).

### Arquivo de ambiente (não usado com Docker Compose ou Kubernetes)

`settings.dist.py` lê variáveis de ambiente de um arquivo cujo nome é especificado na variável de ambiente `DD_ENV_PATH`. Se essa variável não estiver definida, o padrão `.env.prod` é usado. O arquivo deve estar localizado no diretório `dojo/settings`.

Um exemplo pode ser encontrado em [`template_env`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-env).

### local_settings.py

`local_settings.py` pode conter personalizações mais complexas, como adicionar entradas de MIDDLEWARE ou INSTALLED_APP.
Este arquivo é processado *depois* que settings.dist.py é processado, então você pode modificar as configurações entregues pelo DefectDojo prontas para uso.
 O arquivo deve estar localizado no diretório `dojo/settings`. As variáveis de ambiente neste arquivo não devem ter o prefixo `DD_`.
Se o arquivo estiver ausente, sinta-se à vontade para criá-lo. Não edite `settings.dist.py` diretamente.

Um exemplo pode ser encontrado em [`dojo/settings/template-local_settings`](https://github.com/DefectDojo/django-DefectDojo/blob/master/dojo/settings/template-local_settings).

No modo de release do Docker Compose, os arquivos em `docker/extra_settings/` (relativo ao arquivo `docker-compose.yml`) serão copiados para `dojo/settings/` no container docker durante a inicialização.

`local_settings.py` também pode ser usado no Kubernetes. A variável `localsettingspy` será armazenada como ConfigMap e montada no local responsável dos containers.

## Configuração na UI

Usuários com status de superusuário podem configurar mais opções através da UI em `Configuration` / `System Settings`.
