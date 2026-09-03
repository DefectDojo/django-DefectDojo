---
title: Instalando no Docker Compose
description: Instale o DefectDojo Pro auto-hospedado em um único host usando o dojo-compose-cli,
  com o PostgreSQL em um servidor separado
draft: false
weight: 15
audience: pro
---

Esta página aborda a instalação do DefectDojo Pro no Docker Compose, que é o mais simples dos dois modelos auto-hospedados e a escolha certa se você ainda não executa Kubernetes.

O resultado são dois hosts. Um executa a aplicação e seus serviços de suporte sob o Docker Compose, e outro executa o PostgreSQL. Você pode apontar para um banco de dados gerenciado em vez de executar o seu próprio, e para avaliação você pode executar o banco de dados em um container no host da aplicação, embora isso não seja o que você deseja para dados de produção.

Quase todo o trabalho é feito pelo `dojo-compose-cli`, que o DefectDojo fornece junto com sua licença. Seu comando `first-install` é um assistente interativo que configura a implantação, baixa as imagens, inicia tudo e registra um serviço systemd.

## Antes de começar

Dimensione a implantação primeiro. As orientações de dimensionamento de hardware nesta seção abordam o que provisionar tanto para o host da aplicação quanto para o banco de dados.

O Ubuntu 24.04 LTS é o sistema operacional suportado para esta instalação. Atualize-o completamente antes de começar. A instalação executa comandos como root, então você precisa de `sudo` ou de um shell root em ambos os hosts.

Você precisará de dois arquivos do DefectDojo, que chegam com sua assinatura: o pacote `dojo-compose-cli` e seu arquivo de licença, geralmente chamado `dojopro.lic`. Entre em contato com seu representante de conta ou [support@defectdojo.com](mailto:support@defectdojo.com) se não os tiver.

## Configure o banco de dados

O DefectDojo Pro requer PostgreSQL 16 ou mais recente.

### Usando um banco de dados gerenciado

Se você estiver usando um serviço PostgreSQL gerenciado, siga a documentação desse provedor para criar a instância e, em seguida, crie o seguinte:

- Um banco de dados chamado `dojodb`
- Um usuário de banco de dados chamado `dojodbusr`, com todos os privilégios em `dojodb`, definido como seu proprietário

Anote o nome do host, a porta (se não for a padrão 5432) e as credenciais. Você precisará delas durante a instalação.

### Executando o PostgreSQL você mesmo

No Ubuntu 24.04, o PostgreSQL 16 está nos repositórios padrão:

```bash
apt update
apt -y install postgresql postgresql-contrib
```

Crie os bancos de dados e o usuário da aplicação. O DefectDojo usa um segundo banco de dados para seu serviço de orquestração, então crie ambos:

```sql
CREATE USER dojodbusr;
CREATE DATABASE dojodb;
CREATE DATABASE "dojodb-ddorch";
ALTER USER dojodbusr WITH ENCRYPTED PASSWORD '<strong-password>';
GRANT ALL PRIVILEGES ON DATABASE dojodb TO dojodbusr;
GRANT ALL PRIVILEGES ON DATABASE "dojodb-ddorch" TO dojodbusr;
ALTER DATABASE dojodb OWNER TO dojodbusr;
ALTER DATABASE "dojodb-ddorch" OWNER TO dojodbusr;
```

Use uma senha alfanumérica. Caracteres especiais precisam ser codificados em URL mais tarde, quando a senha entra em uma string de conexão, e essa é uma etapa fácil de errar.

Em seguida, faça o banco de dados escutar conexões vindas do host da aplicação. Em `/etc/postgresql/16/main/postgresql.conf`, defina `listen_addresses` para o próprio endereço do servidor de banco de dados, ou para `*` se preferir não fixá-lo:

```bash
listen_addresses = '<db-server-address>'
```

E em `/etc/postgresql/16/main/pg_hba.conf`, adicione três linhas autorizando o host da aplicação. Restringir ao endereço do host da aplicação é melhor do que abrir para tudo:

```text
host  dojodb         dojodbusr  <app-server-address>/32  scram-sha-256
host  dojodb-ddorch  dojodbusr  <app-server-address>/32  scram-sha-256
host  postgres       dojodbusr  <app-server-address>/32  scram-sha-256
```

Reinicie para que ambas as alterações entrem em vigor:

```bash
systemctl restart postgresql
```

## Prepare o host da aplicação

### Conectividade de saída

Em uma rede restrita, o host da aplicação precisa de acesso de saída para o seguinte. Todos são HTTPS na porta 443, salvo indicação contrária.

| Destino | Finalidade | Obrigatório |
| --- | --- | --- |
| `us-south1-docker.pkg.dev` | O registro de containers do DefectDojo Pro | Sim |
| Seu host de banco de dados, geralmente porta 5432 | Aplicação para banco de dados | Sim |
| Os repositórios de pacotes da sua distribuição | Dependências do sistema operacional durante a configuração | Sim |
| `download.docker.com` | Pacotes do Docker Engine durante a configuração | Sim |
| `api.first.org` | Pontuações de previsão de exploração EPSS | Opcional |
| `www.cisa.gov` | O catálogo KEV de vulnerabilidades exploradas conhecidas | Opcional |

Inclua na lista de permissões por nome de host, e não por endereço. O registro fica atrás de uma rede de distribuição de conteúdo, então seus endereços variam por localização e mudam com o tempo.

Se o host acessa a internet através de um proxy de saída, veja [Executando o DefectDojo Atrás de um Proxy HTTPS de Encaminhamento](/onprem_deployment/forward_proxy/). Se ele não tiver nenhuma rota para a internet, siga o procedimento de instalação air-gapped desta seção.

### Confirme que o banco de dados está acessível

Instale as ferramentas de cliente e conecte-se antes de prosseguir. Um problema de banco de dados é muito mais fácil de diagnosticar agora do que no meio da instalação:

```bash
apt update
apt -y install postgresql-client-common postgresql-client-16
psql -h <db-host> -p 5432 -d dojodb -U dojodbusr -W
```

### Instale o Docker Engine

Siga as [instruções de instalação do Docker Engine para Ubuntu](https://docs.docker.com/engine/install/ubuntu/). Use a documentação oficial do Docker, e não uma cópia, já que as etapas mudam com o tempo. Instale o pacote `docker-compose-plugin` junto com o engine, o que essas instruções incluem por padrão.

Em seguida, adicione seu usuário ao grupo `docker` e aplique a nova associação:

```bash
sudo usermod -aG docker "$USER"
newgrp docker
docker info
```

## Instale o DefectDojo

Copie o pacote da CLI e seu arquivo de licença para o host da aplicação, no mesmo diretório, e extraia a CLI:

```bash
tar -xzvf dojo-compose-cli_*.tar.gz
```

Em seguida, execute o instalador a partir desse diretório:

```bash
sudo ./dojo-compose-cli first-install
```

O assistente solicitará o seguinte.

| Prompt | O que é |
| --- | --- |
| `DOJO_CLI_KEY` | Uma chave de criptografia para a configuração que a CLI armazena em disco. Escolha-a agora e guarde-a, pois comandos posteriores vão precisar dela. |
| DefectDojo Version | A versão a ser instalada. |
| Deploy Version | Os arquivos de implantação a serem usados. Defina-o com o mesmo valor da versão. |
| Deploy Type | `separate-db` para um banco de dados em seu próprio host, ou `containerized-db` para executar o PostgreSQL em um container. |
| Database Connection Type | Escolha Single Line e forneça a string de conexão completa. |
| Database URL | `postgres://<user>:<password>@<host>:5432/dojodb`. Deve começar com `postgres://`, e não com `postgresql://`. |
| `DD_ALLOWED_HOSTS` | Os cabeçalhos de host aos quais a aplicação vai responder. |
| `DD_SITE_URL` | A URL completa onde os usuários acessam o DefectDojo, por exemplo `https://defectdojo.internal.example.com`. |

Duas coisas vale a pena saber sobre esses prompts. Forneça a conexão do banco de dados como uma única linha, e não valor por valor, já que o caminho valor por valor atualmente não pergunta pelo nome de usuário. E se a senha contiver caracteres como `!`, `@` ou `#`, codifique-os em URL na string de conexão.

Em seguida, o instalador baixa as imagens, inicia a stack, cria um serviço systemd e imprime as credenciais de administrador geradas. **Salve essas credenciais antes de fechar o terminal. Elas não são mostradas novamente.**

Quando terminar, o DefectDojo estará disponível na URL do site que você forneceu.

## O que a instalação criou

| Item | Localização |
| --- | --- |
| Binário da CLI | `/usr/bin/dojo-compose-cli` |
| Arquivos da aplicação, arquivo compose, configuração do nginx, mídia | `/opt/dojo/` |
| Arquivo de licença | `/etc/defectdojo/dojopro.lic` |
| Configuração criptografada da CLI | `/etc/defectdojo/compose.config` |
| Certificados TLS | `/opt/dojo/certs/` |
| Suas personalizações | `/opt/dojo/customizations/` |
| Serviço systemd | `/etc/systemd/system/defectdojo-compose.service` |

Também cria um usuário e grupo `dojosrv`, que são proprietários dos arquivos da aplicação.

A stack em execução é composta pela aplicação Django, um container separado que trata as importações de scans, o nginx, um worker e agendador Celery, o Valkey para cache e enfileiramento, o serviço de conectores e o servidor MCP. `docker ps` os lista.

No dia a dia, estes são os comandos de que você precisa:

```bash
systemctl status defectdojo-compose
dojo-compose-cli app start
dojo-compose-cli app stop
dojo-compose-cli app restart
docker logs dojo
```

Use `app restart` depois de alterar qualquer configuração, já que ele recria os containers para que os novos valores sejam aplicados.

## Substitua o certificado TLS

A instalação vem com um certificado autoassinado para que o site funcione imediatamente. Substitua-o pelo seu próprio certificado, sobrescrevendo dois arquivos, mantendo os nomes exatamente como estão:

- `/opt/dojo/certs/dojo.crt`
- `/opt/dojo/certs/dojo.key`

Depois, execute `dojo-compose-cli app restart` para aplicá-los.

## Redefina a senha do administrador

Se você perder a senha gerada, redefina-a a partir do host da aplicação. O DefectDojo precisa estar em execução:

```bash
dojo-compose-cli app change-password
```

## Atualizando

Faça backup do seu banco de dados primeiro, e leia as notas de versão de todas as versões entre a sua atual e a de destino, e não apenas a de destino. Veja as [notas de atualização](/releases/os_upgrading/upgrading_guide/).

A CLI pode fazer toda a atualização, solicitando a versão:

```bash
dojo-compose-cli app upgrade
```

Se preferir fazer isso em etapas, pare a aplicação, defina a nova versão, baixe os arquivos de implantação correspondentes e, então, inicie novamente:

```bash
dojo-compose-cli app stop
dojo-compose-cli config set --version x.y.z --deploy-version x.y.z
dojo-compose-cli deploy download
dojo-compose-cli app start
```

A etapa de download compara o `docker-compose.yml`, a configuração do nginx e o `local_settings.py` recebidos com o que você já possui, e avisa quando eles diferem para que você possa reconciliar suas alterações. Adicionar `--overwrite` aceita as novas versões desses arquivos e descarta as modificações locais feitas neles, então use-o com cautela.

Mantenha suas próprias configurações em `/opt/dojo/customizations/local_settings.py`. Esse arquivo é seu e sobrevive às atualizações.

## Referência de comandos

`dojo-compose-cli --help` lista tudo, e cada subcomando também aceita `--help`. Os comandos que você provavelmente vai precisar:

| Comando | O que faz |
| --- | --- |
| `first-install` | Instalação interativa inicial |
| `app start`, `app stop`, `app restart` | Controla a stack |
| `app upgrade` | Atualiza para uma versão mais recente |
| `app pull-images`, `app purge-images` | Busca ou remove as imagens configuradas |
| `app change-password` | Redefine a senha do administrador, com a aplicação em execução |
| `config print` | Mostra a configuração atual |
| `config set` | Define a versão, a versão de implantação, o tipo de implantação ou o modo air-gapped |
| `config rotate-secret` | Rotaciona a chave que criptografa a configuração armazenada |
| `environment print`, `environment add`, `environment remove` | Gerencia variáveis de ambiente |
| `deploy download` | Busca os arquivos de implantação da versão configurada |
| `license print`, `license status`, `license update` | Inspeciona e atualiza sua licença |
| `validate db-connection` | Verifica a string de conexão do banco de dados |
| `validate deploy-version` | Verifica se os arquivos de implantação correspondem à versão configurada |
| `diagnostics collect` | Reúne um pacote de diagnóstico para uma solicitação de suporte |
| `register` | Autentica no registro de containers |
| `update-binary` | Atualiza a própria CLI |

A maioria dos comandos precisa de `DOJO_CLI_KEY`, já que a configuração é criptografada em repouso. Exporte-a para sua sessão, ou passe-a pelo `sudo` com `sudo -E`:

```bash
export DOJO_CLI_KEY="your-key"
```

## Dúvidas ou suporte

Se uma instalação não for concluída, `dojo-compose-cli diagnostics collect` reúne um pacote de relatório que é a forma mais rápida de conseguirmos ajudar. Envie-o, junto com o que você estava executando quando falhou, para [support@defectdojo.com](mailto:support@defectdojo.com).
