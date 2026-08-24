---
title: Editar a Documentação
description: Como editar a documentação
draft: false
weight: 4
audience: opensource
aliases:
- /pt-br/en/open_source/contributing/documentation
---

A documentação é construída com [Hugo](https://gohugo.io/) e usa uma variação do tema [Doks](https://getdoks.org/).

Os arquivos estáticos do site são gerados com Github actions e publicados no branch gh-pages.

## Como executar uma prévia local

1. [Instale o Hugo](https://gohugo.io/getting-started/installing/). Certifique-se de instalar a versão extended, com suporte a Sass/SCSS. Observe que há vários pacotes Linux disponíveis no [Hugo GitHub](https://github.com/gohugoio/hugo/releases)
2. Instale o tema necessário usando Node.js: `cd docs` e depois `npm install`.
3. Para executar o servidor local dos Docs, `cd docs` para acessar a pasta docs, e inicie o servidor de desenvolvimento do Hugo executando `npm run dev`.  O hot reloading é suportado - as páginas serão atualizadas automaticamente conforme as alterações, enquanto o servidor estiver em execução.
4. Acesse [http://localhost:1313](http://localhost:1313).

## Diretrizes de contribuição

Neste momento, nossa documentação é mantida majoritariamente pela equipe do DefectDojo Pro, mas ainda assim recebemos contribuições da comunidade para os docs.

* Observe que nossa funcionalidade de Search usa um índice externo que aponta para **docs.defectdojo.com** - portanto, você não conseguirá usar o Search para encontrar páginas que estejam em dev.  Em vez disso, consulte seu arquivo local sitemap.xml para encontrar quaisquer novas URLs que você tenha criado: `http://localhost:1313/sitemap.xml`
* Nossos docs são atualmente escritos para dois públicos: Open Source e Pro, então inclua um rótulo apropriado no front matter do Hugo, desta forma:

```
---
title: "Your great article"
audience: opensource
---
```

* Não use caminhos de link relativos: `[link](../your_article/)`.  Embora tecnicamente sejam 'válidos' no Hugo, isso fará com que nossos testes unitários não passem.

## Testes unitários para os docs

Os docs do DefectDojo usam o Lychee para verificar erros 404 e outros erros de link.  O CI executa duas verificações: o site de docs renderizado, e quaisquer URLs de `docs.defectdojo.com` fixadas diretamente no código do app Django (templates e settings).  Ambas usam um `--remap` para que as URLs absolutas de `docs.defectdojo.com` sejam resolvidas em relação ao site recém-construído.  Para executar ambas localmente a partir da raiz do repositório:

```
cd docs && rm -rf public/ && hugo --minify --gc --config config/production/hugo.toml && cd ..

lychee --offline --no-progress \
  --root-dir "$PWD/docs/public" \
  --remap "https://docs.defectdojo.com file://$PWD/docs/public" \
  './docs/public/**/*.html'

lychee --offline --no-progress \
  --root-dir "$PWD/docs/public" \
  --remap "https://docs.defectdojo.com file://$PWD/docs/public" \
  --exclude '%7[BD]' \
  $(grep -rl 'docs\.defectdojo\.com' dojo/ --include='*.html' --include='*.py' --include='*.tpl')
```

### Sobreposições de tema

Usamos sobreposições de CSS significativas, detalhadas em `docs/layouts`.
