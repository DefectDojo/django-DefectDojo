---
title: Migrando do Open Source para o DefectDojo Pro autogerenciado
description: Mova o banco de dados e os arquivos de mídia do seu DefectDojo open source
  para uma implantação autogerenciada do DefectDojo Pro
draft: false
weight: 6
audience: pro
---

Esta página descreve como mover os dados de uma instância open source do DefectDojo para uma implantação autogerenciada do DefectDojo Pro.

Os exemplos usam a Amazon Web Services, com Docker Compose no EC2 ou Kubernetes no EKS, e o banco de dados no Amazon RDS para PostgreSQL. Essa é a combinação em relação à qual este procedimento foi validado. A mesma sequência se aplica a outros provedores que oferecem PostgreSQL gerenciado e capacidade computacional equivalente, e a hardware on-premise, alterando os comandos específicos do provedor conforme necessário.

Como você hospeda a implantação, seus dados permanecem dentro do seu próprio ambiente durante toda a migração. Você executa a exportação e a restauração, e o suporte do DefectDojo pode ajudar em qualquer etapa. Se a sua instância do DefectDojo Pro for hospedada na nuvem pelo DefectDojo, em vez de autogerenciada, entre em contato com [support@defectdojo.com](mailto:support@defectdojo.com), pois nesse caso é a equipe do DefectDojo que realiza a restauração para você.

Em linhas gerais, você exporta o banco de dados e os arquivos de mídia da instância open source, os restaura no banco de dados e no armazenamento usados pela sua implantação do Pro, aponta o Pro para o banco de dados restaurado e, em seguida, valida o resultado.

## Antes de começar

Confirme os itens a seguir antes de exportar qualquer coisa.

Seu mecanismo de banco de dados. O DefectDojo é compatível com PostgreSQL. O suporte a MySQL foi descontinuado e depois [removido na versão 2.37.0](/releases/os_upgrading/2.37/), portanto uma instância mais antiga ainda rodando em MySQL precisa ser convertida para PostgreSQL antes de ser migrada. Entre em contato com o suporte se este for o seu caso.

Onde seu banco de dados é executado. Pode ser um container da configuração padrão do Docker Compose, ou um serviço separado no mesmo host, em outra VM, ou em um serviço gerenciado como Amazon RDS ou Cloud SQL. O comando de exportação varia dependendo de qual dos dois é o seu caso.

Sua versão open source. Encontre-a no rodapé da interface, ou a partir das tags de implantação e das versões de imagem. Todos os releases 2.x podem ser migrados com este procedimento. Se você estiver rodando a 3.0.0, 3.0.1, 3.0.2 ou 3.0.100, faça upgrade para a [3.0.200](/releases/os_upgrading/3.0.200/) ou posterior antes de começar. Revise as [notas de upgrade](/releases/os_upgrading/upgrading_guide/) de cada versão entre a sua versão atual e a versão para a qual você vai atualizar.

Alinhamento de versões. Sua versão open source deve corresponder, ou ficar o mais próxima possível, da versão do DefectDojo Pro para a qual você está migrando. Na primeira inicialização, o Pro executa as migrações de banco de dados que atualizam o schema para sua própria versão, então uma diferença grande entre as versões aumenta o risco de uma migração longa ou malsucedida. Alinhe as versões antes de gerar o dump.

Seu banco de dados de destino. Provisione uma versão principal do PostgreSQL atualmente suportada, 16 ou mais recente, e nunca mais antiga que a versão usada pela sua instância open source, pois um dump não pode ser restaurado em uma versão principal mais antiga. Na AWS, coloque a instância RDS na mesma VPC da sua infraestrutura de computação do Pro e permita tráfego de entrada na porta 5432 a partir do host de onde você restaura.

Seu host de restauração. Você precisa de uma máquina na mesma rede do banco de dados, com as ferramentas de cliente PostgreSQL `pg_restore` e `psql` instaladas. Na AWS, use uma instância EC2 na mesma VPC, idealmente na mesma Availability Zone da instância RDS.

Espaço livre em disco. O servidor de origem precisa de espaço para o dump do banco de dados e o arquivo compactado de mídia antes que você os transfira.

## Etapa 1: exporte seu banco de dados

A configuração padrão do Docker Compose usa `defectdojo` tanto como nome de usuário quanto como nome do banco de dados. Esses valores podem ser sobrescritos, então verifique o valor de `DD_DATABASE_URL` no seu arquivo `docker-compose.yml` ou `.env`. A string de conexão padrão é:

```text
postgresql://defectdojo:defectdojo@postgres:5432/defectdojo
```

Nos comandos abaixo, substitua `<db_username>`, `<database_name>` e `<postgres_container_name>` pelos seus próprios valores. Encontre o nome do container com `docker ps`.

É recomendado um dump compactado no formato customizado (custom-format). O `pg_restore` pode carregá-lo diretamente, e isso evita a maior parte dos problemas de propriedade (ownership) e de roles que surgem durante uma restauração em um banco de dados gerenciado.

Para um PostgreSQL em container, que é a configuração padrão do Docker Compose:

```bash
docker exec <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Se o banco de dados exigir uma senha, passe-a no ambiente:

```bash
docker exec -e PGPASSWORD='your_password' <postgres_container_name> pg_dump \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Para um PostgreSQL externo ou remoto, como uma VM separada, Amazon RDS ou Cloud SQL:

```bash
pg_dump -h <remote_ip_or_hostname> -p 5432 \
  -U <db_username> -Fc <database_name> > ./defectdojo-backup.dump
```

Um dump SQL em texto simples, produzido ao omitir `-Fc`, também funciona. Ele tende a incluir instruções `CREATE ROLE`, `ALTER ROLE` e `CREATE DATABASE` que um banco de dados gerenciado vai rejeitar, então consulte a observação na Etapa 4 caso use esse formato.

## Etapa 2: exporte seus arquivos de mídia

O DefectDojo armazena artefatos enviados, como capturas de tela, modelos de ameaças e documentos de aceitação de risco, em um diretório de mídia. Os arquivos de scan usados para importação e reimportação não são mantidos em disco pelo DefectDojo open source, já que são descartados após serem processados, então o diretório de mídia contém apenas artefatos enviados pelo usuário.

A localização do diretório depende de como você fez a implantação:

| Método de implantação | Caminho de mídia típico |
| --- | --- |
| Docker Compose | Volume nomeado `defectdojo_media`, montado em `/app/media` |
| Bare metal | `/opt/dojo/media`, ou o caminho definido em `DD_MEDIA_ROOT` |
| Kubernetes | Volume persistente montado em `/app/media` |

Compacte o diretório em um único arquivo. A partir de um volume nomeado:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine tar czf /backup/defectdojo_media.tar.gz -C /media .
```

A partir de um caminho em disco:

```bash
tar czf defectdojo_media.tar.gz -C /opt/dojo/media .
```

## Etapa 3: nomeie seus arquivos

Inclua sua versão open source em ambos os nomes de arquivo, para que a versão em jogo fique inequívoca durante a restauração. Para uma instância rodando a 2.38.1:

| Arquivo | Renomeado para |
| --- | --- |
| `defectdojo-backup.dump` | `defectdojo-v2.38.1-backup.dump` |
| `defectdojo_media.tar.gz` | `defectdojo-v2.38.1-media.tar.gz` |

Transfira ambos os arquivos para o seu host de restauração. Você pode copiá-los diretamente com uma ferramenta como `scp`, ou colocá-los em um armazenamento de objetos privado na sua própria conta e depois baixá-los para o host de restauração. Na AWS isso significa um bucket S3 privado e `aws s3 cp`. De qualquer forma, os dados permanecem dentro do seu próprio ambiente.

## Etapa 4: restaure o banco de dados

Execute a restauração a partir do seu host de restauração, apontando para o endpoint do banco de dados. Os serviços gerenciados de PostgreSQL diferem quanto ao que suportam nesse ponto. O Amazon RDS não tem uma importação em uma única etapa de um arquivo de dump a partir de um bucket, então o caminho suportado é um `pg_restore` executado do lado do cliente.

1. Crie o banco de dados e a role da aplicação. Conecte-se como seu usuário master e crie o banco de dados de destino e a role que o dump espera. Os padrões são `defectdojo` para ambos, então use seus próprios valores se você os tiver sobrescrito.

```sql
CREATE ROLE defectdojo WITH LOGIN PASSWORD '<app_db_password>';
CREATE DATABASE defectdojo OWNER defectdojo;
```

2. Restaure o dump. Para um dump em formato customizado, use `--no-owner` e `--no-privileges` para que a restauração não tente reatribuir a propriedade a roles que não existem no destino. Um banco de dados gerenciado não concede um superusuário verdadeiro, então uma restauração que tente fazer isso vai falhar.

```bash
pg_restore -v --no-owner --no-privileges \
  -h <db-endpoint> -U <master_user> -d defectdojo \
  -j 2 defectdojo-v<VERSION>-backup.dump
```

Para um dump SQL em texto simples, primeiro comente ou remova quaisquer instruções `CREATE ROLE`, `ALTER ROLE`, `CREATE DATABASE` e `ALTER DATABASE ... OWNER`, e então carregue-o:

```bash
gunzip -c defectdojo-v<VERSION>-backup.sql.gz | \
  psql -h <db-endpoint> -U <master_user> -d defectdojo
```

Se a restauração relatar erros, capture a saída e entre em contato com o suporte antes de remover qualquer outra coisa do dump. Remover conteúdo em excesso pode deixar o banco de dados em um estado inconsistente, mais difícil de diagnosticar do que o erro original.

## Etapa 5: restaure seus arquivos de mídia

Coloque o conteúdo do arquivo de mídia no local de onde a sua implantação do Pro lê os arquivos enviados. A aplicação procura por eles em `/app/media`, que sua implantação sustenta com um bind mount ou um volume persistente. Consulte a documentação de instalação fornecida com sua licença para saber o caminho de host ou o volume usado pela sua implantação.

Para uma implantação com Docker Compose sustentada por um volume nomeado:

```bash
docker run --rm \
  -v defectdojo_media:/media \
  -v $(pwd):/backup \
  alpine sh -c "tar xzf /backup/defectdojo-v<VERSION>-media.tar.gz -C /media"
```

Para uma implantação em Kubernetes, extraia o arquivo localmente e copie-o para o pod do Django, que grava no persistent volume claim montado em `/app/media`:

```bash
kubectl cp ./media-extracted/. <namespace>/<django-pod-name>:/app/media/
```

## Etapa 6: aponte o DefectDojo Pro para o banco de dados restaurado

Atualize a conexão do banco de dados para que o Pro use o banco de dados que você acabou de restaurar e, em seguida, inicie a aplicação. Na primeira inicialização, o Pro executa as migrações de banco de dados que atualizam o schema da sua versão open source para a versão Pro. Dependendo do tamanho do seu banco de dados e da diferença entre as versões, isso pode levar algum tempo, e a aplicação não fica disponível até que o processo termine.

Para implantações com Docker Compose, defina a URL do banco de dados na configuração da sua implantação e reinicie a stack. A chave de configuração e o comando exatos dependem da versão do `dojo-compose-cli` que foi fornecida a você, então siga a documentação de instalação que acompanha sua licença. A string de conexão tem este formato:

```text
postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Para implantações em Kubernetes, defina a URL do banco de dados nos seus values do Helm e reimplante:

```yaml
databaseUrl: postgresql://defectdojo:<app_db_password>@<db-endpoint>:5432/defectdojo
```

Quais recursos do Pro estão disponíveis para a sua implantação depende da sua licença e de como você implanta, já que alguns deles não se aplicam a uma instalação autogerenciada. O DefectDojo confirma o conjunto que se aplica ao seu caso durante a migração.

## Etapa 7: valide seus dados

Depois que a aplicação estiver em execução com o banco de dados restaurado:

1. Faça login na sua implantação do DefectDojo Pro.
2. Verifique se seus Assets, Organizations, Engajamentos, Testes e Achados estão presentes. Assets e Organizations eram chamados de Produtos e Product Types no open source.
3. Baixe um arquivo enviado representativo a partir da interface, por exemplo um anexo em um Achado, Teste ou Engajamento, para confirmar que a restauração de mídia funcionou.
4. Verifique se as contas de usuário e os grupos estão intactos. As configurações de SSO e outras configurações de autenticação geralmente precisam ser reconfiguradas para a nova implantação.
5. Relate quaisquer discrepâncias ao seu contato no DefectDojo.

## Planejando a virada (cutover)

O dump é uma captura de um ponto específico no tempo, então tudo o que for criado na instância open source depois que você o gerar não estará na implantação do Pro. Para evitar perda de dados, congele a instância open source para o dump final e a virada, ou execute a migração durante um período de baixa atividade.

Vale a pena investir tempo em um ensaio (dry run). Migre primeiro uma cópia recente, valide-a e depois repita o processo para a virada real. A segunda execução é mais rápida e indica quanto tempo a migração de schema da Etapa 6 vai levar.

## Checklist de migração

- Mecanismo de banco de dados, localização do banco de dados e versão open source identificados
- Versão open source alinhada com a versão Pro de destino
- PostgreSQL de destino provisionado, acessível a partir de um host de restauração com as ferramentas de cliente PostgreSQL
- Banco de dados exportado, com um dump em formato customizado quando possível
- Diretório de mídia localizado e compactado
- Ambos os arquivos nomeados com a versão open source
- Banco de dados e role da aplicação criados no destino
- Dump restaurado, com a saída da restauração revisada em busca de erros
- Arquivos de mídia restaurados no caminho ou volume usado pela sua implantação
- Pro apontado para o banco de dados restaurado e iniciado, com as migrações de schema concluídas
- Dados validados na nova implantação

## Dúvidas ou suporte

O DefectDojo dá suporte a essa migração de ponta a ponta. Para obter ajuda em qualquer etapa, entre em contato com o seu representante de conta ou com [support@defectdojo.com](mailto:support@defectdojo.com).
