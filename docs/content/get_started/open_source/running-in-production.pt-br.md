---
title: Executando em produção
description: Para uso em ambientes de produção, recomenda-se ajustes de performance
  e backups.
draft: false
weight: 4
audience: opensource
aliases:
- /pt-br/en/open_source/installation/running-in-production
---

## Uso em produção (com Docker compose)

O arquivo docker-compose.yml neste repositório é totalmente funcional para avaliar o DefectDojo no seu ambiente local.

Embora o Docker Compose seja um dos métodos de instalação suportados para implantar um DefectDojo em containers em um ambiente de produção, o arquivo docker-compose.yml não se destina ao uso em produção sem antes ser personalizado para sua situação específica.

Veja [Executando com Docker Compose](https://github.com/DefectDojo/django-DefectDojo/blob/master/readme-docs/DOCKER.md) para mais informações sobre como executar o DefectDojo com Docker Compose.

### Requisitos do sistema

É recomendado usar um servidor de banco de dados dedicado, e não o banco de dados PostgreSQL pré-configurado. Isso melhorará significativamente a performance do DefectDojo.

#### Tamanho da instância

Com um banco de dados separado, as recomendações mínimas para executar o DefectDojo são:

-   2 vCPUs
-   8 GB de RAM
-   10 GB de espaço em disco (lembre-se, seu banco de dados não está aqui \-- então
     o que você tiver para o seu S.O. deve ser suficiente). Você poderia alocar
    um disco diferente do seu S.O.\'s para possíveis melhorias
    de performance.

### Segurança
Verifique a configuração do `nginx` e outros aspectos de runtime, como cabeçalhos de segurança, para atender aos seus requisitos de compliance.
Altere a chave de criptografia AES256 `&91a*agLqesc*0DJ+2*bAbsUZfR*4nLw` em `docker-compose.yml` para algo único para sua instância.
Esta chave de criptografia é usada para criptografar chaves de API e outras credenciais armazenadas no Defect Dojo para se conectar a ferramentas externas como o SonarQube. Uma chave pode ser gerada de várias formas, por exemplo usando um gerenciador de senhas ou `openssl`:

```
     openssl rand -base64 32
```
```
      DD_CREDENTIAL_AES_256_KEY: "${DD_CREDENTIAL_AES_256_KEY:-<PUT THE GENERATED KEY HERE>o}"
```

## Backup de arquivos

Em ambos os casos (banco de dados dedicado ou em container), se você estiver fazendo self-hosting, é recomendado que você implemente e crie backups periódicos dos seus dados.

### Arquivos de mídia

Os arquivos de mídia para arquivos enviados, incluindo modelos de ameaça e aceitação de risco, são armazenados em um volume docker. Esse volume precisa ser copiado (backup) regularmente.

## Ajustes de performance

### uWSGI

Por padrão (exceto no modo `ptvsd` para fins de depuração), o uWSGI irá
lidar com 16 conexões simultâneas.

Com base nas suas configurações de recursos, você pode ajustar:

-   `DD_UWSGI_NUM_OF_PROCESSES` para o número de processos gerados.
    (padrão 4)
-   `DD_UWSGI_NUM_OF_THREADS` para o número de threads nesses
    processos. (padrão 4)

Por exemplo, você pode ter 4 processos com 6 threads cada, resultando em 24
conexões simultâneas.

### Celery worker

Por padrão, um único celery worker mono-processo é gerado. Ao armazenar uma grande quantidade de achados ou executar importações grandes, pode ser útil ajustar esses parâmetros para evitar a falta de recursos.

As variáveis a seguir podem ser alteradas para aumentar a performance do worker, mantendo um único container celery.

-   `DD_CELERY_WORKER_POOL_TYPE` permite alternar para `prefork`.
    (padrão `solo`)

Ao habilitar o `prefork`, as variáveis abaixo devem
ser usadas. Veja o
Dockerfile.django-* para referências no arquivo.

-   `DD_CELERY_WORKER_AUTOSCALE_MIN` tem como padrão 2.
-   `DD_CELERY_WORKER_AUTOSCALE_MAX` tem como padrão 8.
-   `DD_CELERY_WORKER_CONCURRENCY` tem como padrão 8.
-   `DD_CELERY_WORKER_PREFETCH_MULTIPLIER` tem como padrão 128.

Você pode executar o seguinte comando para ver a configuração:

`docker compose exec celerybeat bash -c "celery -A dojo inspect stats"`
e veja o que está em vigor.

### Import assíncrono: descontinuado
Este recurso foi removido na versão 2.47.0
