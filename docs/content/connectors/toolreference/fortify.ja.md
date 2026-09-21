---
title: "Fortify"
description: "DefectDojo で Fortify の Upstream Connector をセットアップする方法"
weight: 59
audience: pro
---
Fortifyコネクタは、Fortify（OpenText/Micro Focus）からSAST/DASTの結果をインポートします。同じプラットフォームを共有する2つのエディション、**SSC**（Software Security Center、自己ホスト型）と**Fortify on Demand（FoD）**（SaaS）の両方に対応しています。アカウント全体を同期し、DefectDojoはすべてのアプリケーション（SSCのproject version / FoDのrelease）を検出してそれぞれについてレコードを作成し、そのアプリケーションのissueを検出事項としてインポートします。

#### Prerequisites

- **SSC**: **FortifyToken**が必要です。これはSSC UIの**Administration → Token Management**で作成します（CIToken/UnifiedLoginToken）。
- **FoD**: **OAuth2 APIキー**が必要です。これは**Settings → API**から取得するClient IDとClient Secretです（`api-tenant`スコープを付与）。

トークンとOAuthのsecretがログに記録されることはありません。

#### Connector Mappings

1. **Location**フィールドにFortifyのベースURLを入力します。SSCの場合はサーバーのホスト（コネクタが`/ssc/api/v1`を追加します）、FoDの場合はリージョンに応じたAPIホスト（例: `https://api.ams.fortify.com`）を入力します。
2. **Edition**を`SSC`または`FoD`に設定します。
3. **FoD**の場合は、OAuthの**Client ID**を入力します。SSCの場合は空欄のままにします。
4. **Token / Client Secret**には、SSCのFortifyTokenまたはFoDのOAuthクライアントシークレットを入力します。
5. 必要に応じて、インポートする検出事項を制限するために**Minimum Severity**を設定します。

DefectDojoは、Fortifyの各**アプリケーション**をレコードにマッピングし、各**issue**を検出事項にマッピングします。深刻度はFortify独自の**friority**評価（重大/高/中/低）に基づき、タイトルはissueのカテゴリとファイル・行番号を組み合わせたものになります。また、ファイルパス、行番号、kingdom、analyzer、engine typeが引き継がれます。静的解析エンジン（SCA）のissueは静的検出事項として、WebInspect（DAST）のissueは動的検出事項として記録されます。抑制済み・削除済み・非表示のissueはスキップされ、「Not an Issue」と判定されたissueは誤検知としてマークされ、「Exploitable」/レビュー済みのissueは検証済みとしてマークされます。

詳細については、[Fortify SSC](https://www.microfocus.com/documentation/fortify-software-security-center/)および[Fortify on Demand](https://api.ams.fortify.com/swagger/ui)のAPIドキュメントを参照してください。
