---
title: ドキュメントの修正
description: ドキュメントを修正する方法
draft: false
weight: 4
audience: opensource
aliases:
- /ja/en/open_source/contributing/documentation
---

ドキュメントは[Hugo](https://gohugo.io/)で構築されており、[Doks](https://getdoks.org/)テーマの派生版を使用しています。

Webサイトの静的ファイルはGitHub Actionsでビルドされ、gh-pagesブランチに公開されます。

## ローカルプレビューの実行方法

1. [Hugoをインストールします](https://gohugo.io/getting-started/installing/)。Sass/SCSSサポート付きのextended版をインストールしていることを確認してください。[Hugo GitHub](https://github.com/gohugoio/hugo/releases)にはさまざまなLinuxパッケージが用意されています。
2. Node.jsを使用して必要なテーマをインストールします。`cd docs`のあと`npm install`を実行します。
3. Docsのローカルサーバーを実行するには、`cd docs`でdocsフォルダに移動し、`npm run dev`を実行してHugoの開発サーバーを起動します。ホットリロードに対応しており、サーバーの稼働中は変更したページが自動的に更新されます。
4. [http://localhost:1313](http://localhost:1313)にアクセスします。

## 貢献ガイドライン

現段階では、ドキュメントは主にDefectDojo Proチームによって保守されていますが、コミュニティからのドキュメントへの貢献も歓迎しています。

* Search機能は**docs.defectdojo.com**を指す外部インデックスを使用している点にご注意ください。そのため、devにあるページはSearchで見つけることができません。代わりに、作成した新しいURLを確認するにはローカルのsitemap.xmlファイルを参照してください: `http://localhost:1313/sitemap.xml`
* 現在のドキュメントはOpen SourceとProという2つの読者層向けに書かれているため、Hugoのフロントマターに適切なラベルを含めてください。以下のようにします。

```
---
title: "Your great article"
audience: opensource
---
```

* 相対リンクパスは使用しないでください: `[link](../your_article/)`。Hugo上では技術的に「有効」であっても、ユニットテストを通過しません。

## ドキュメントのユニットテスト

DefectDojoのドキュメントでは、404やその他のリンクエラーを確認するためにLycheeを使用しています。CIでは、レンダリングされたドキュメントサイトと、Djangoアプリ(テンプレートおよび設定)にハードコードされた`docs.defectdojo.com`のURLの2つをチェックします。どちらも`--remap`を使用し、絶対パスの`docs.defectdojo.com`のURLが新しくビルドされたサイトに対して解決されるようにしています。リポジトリのルートからローカルで両方を実行するには次のようにします。

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

### テーマのオーバーライド

`docs/layouts`に詳しく記載されている、大幅なCSSオーバーライドを使用しています。
