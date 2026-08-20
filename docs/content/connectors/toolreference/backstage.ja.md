---
title: "Backstage"
description: "DefectDojo で Backstage の Upstream Connector をセットアップする方法"
weight: 22
audience: pro
---
Backstage コネクタは**asset connector**です。検出事項をインポートする代わりに、[Backstage](https://backstage.io) の Software Catalog を DefectDojo に取り込み、製品階層とチームの所有関係をそれと同期させます。サービスインベントリと組織構造を Backstage で管理しており、DefectDojo にはそれを手作業ではなく自動的にミラーしてほしい組織向けに設計されています。

#### What gets mapped

| Backstage | DefectDojo |
|---|---|
| **System** | 製品タイプ(System を持たない Component は、設定可能な「Backstage / Uncategorized」製品タイプの下にグループ化されます) |
| **Component** | 製品 — エンティティの `title`(なければ `name` にフォールバック)から命名され、カタログの description が付与されます |
| **Owning Group**(`ownedBy` リレーション) | 製品に紐づく DefectDojo のグループ(デフォルトのロール: Maintainer、設定変更可能) |
| **Owner email**(グループプロファイルの email、または User オーナーの email) | 同じ email を持つ DefectDojo ユーザーが既に存在する場合、そのユーザーが製品メンバーになります(ユーザーが新規作成されることはありません) |
| `metadata.tags`、`spec.type`、`spec.lifecycle`、namespace、domain | `backstage:` プレフィックス付きの製品タグ |
| `metadata.annotations` | レコードに(上限付きで)保存されます。特定の annotation は **Annotation Mappings** を通じて第一級の属性やタグに昇格できます |

レコードはエンティティのサーバー側で割り当てられた `metadata.uid` をキーとするため、Backstage 上でのリネームは次回の同期でマッピング済みの製品を**その場で**更新します。重複は発生しません。製品名は常にカタログに追従します。このコネクタが管理する製品をリネームするには、Backstage 上で Component をリネームしてください(DefectDojo 側でのリネーム、または手動マッピング時に付けたカスタム名は、他の製品と衝突しない限り、次回の同期でカタログ名に合わせて調整されます)。所有者の変更は、製品のグループ割り当てを移動させます。カタログから消えた(または `backstage.io/orphan` annotation が付いた)Component は **MISSING** としてマークされます。DefectDojo が自ら製品を削除することはありません。Domain と Group の階層(親チーム)はタグ/メタデータとしてのみ記録され、追加の階層レベルを作成することはありません。

#### Prerequisites

このコネクタは、Backstage バックエンドに対して**静的な external access token**で認証します。Backstage アプリの設定でトークンを定義し、(推奨として)catalog プラグインに限定してください。

```yaml
backend:
  auth:
    externalAccess:
      - type: static
        options:
          token: ${DEFECTDOJO_BACKSTAGE_TOKEN}
          subject: defectdojo-connector
        accessRestrictions:
          - plugin: catalog
```

強力なランダムトークンを生成し(例えば `openssl rand -hex 32`)、Backstage デプロイの環境変数に保存してください。詳細は [Backstage service-to-service auth documentation](https://backstage.io/docs/auth/service-to-service-auth) を参照してください。

#### Connector Mappings

1. **Location** フィールドに **Backstage バックエンドのルート URL** を入力します。例: `https://backstage.example.com`(コネクタが `/api/catalog` を自動的に付加します)。これは**バックエンド**の URL である必要があり、フロントエンドの Web UI ではありません。
2. **Secret** フィールドに静的な external access token を入力します。

以下はオプションのフィールドです(デフォルトのままにする場合は空欄にしてください)。

* **Namespaces** — インポート対象のカタログ namespace をカンマ区切りで指定します。空欄の場合はすべての namespace をインポートします。
* **Component Types** — `spec.type` の値をカンマ区切りで指定します(例: `service,website`)。空欄の場合はすべてのタイプをインポートします。
* **Page Size** — カタログクエリのページサイズ(1\-500、デフォルト 250)。
* **TLS Verification** — Backstage が DefectDojo で検証できない証明書(内部 CA)を提供している場合にのみ `false` に設定してください。推奨されません。
* **Uncategorized Product Type** — System を持たない Component に使用される製品タイプ(デフォルト `Backstage / Uncategorized`)。
* **Owner Group Role** — マッピングされた製品に対して所有チームに付与されるロール(デフォルト `Maintainer`)。
* **Annotation Mappings** — annotation キーをレコード属性名にマッピングする JSON オブジェクト、または annotation を製品タグとしてインポートするための `"tag"`。例: `{"github.com/project-slug": "GITHUB_PROJECT", "example.com/tier": "tag"}`。

**Auto\-Map** を有効にすると、1 回の Discover \+ Sync で製品タイプ / 製品 / 所有関係の構造全体が手作業なしで構築されます。Auto-Map を無効にした場合、検出された Component はマッピング判断待ちのレコードとして表示されます。

#### Limitations (v1)

* Backstage の**グループメンバーシップは同期されません**。コネクタは所有チームを DefectDojo のグループとして作成・リンクしますが、そのグループへのユーザーの登録は ID プロバイダや管理者に委ねられます。
* Component のみが製品になります。API、Resource、Domain はアセットとしてインポートされません(Domain はタグとして反映されます)。
* タグと annotation は DefectDojo のフィールド上限に収まるよう正規化・制限されます(過大な値は切り詰められます)。

**逆方向についての補足:** Backstage の内部(エンティティページ上)で DefectDojo の検出事項やグレードを表示することは、DefectDojo REST API を利用する Backstage フロントエンドプラグインとして構築するのが自然な発展形ですが、これはこのコネクタの意図的なスコープ外です。このコネクタはあくまでカタログデータを DefectDojo に取り込むだけです。
