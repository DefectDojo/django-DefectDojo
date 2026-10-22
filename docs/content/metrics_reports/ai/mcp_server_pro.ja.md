---
title: MCP サーバー
description: DefectDojo の MCP サーバーを使用すると、DefectDojo Pro で LLM を利用できます
draft: false
audience: pro
weight: 23
aliases:
- /ja/en/ai/mcp_server_pro
---

<span style="background-color:rgba(242, 86, 29, 0.3)">注: AI 機能は DefectDojo Pro 専用の機能です。</span>

DefectDojo の Model Context Protocol (MCP) サーバーにより、大規模言語モデル (LLM) が DefectDojo の脆弱性管理データと高度にインタラクトできるようになります。単にデータを転送するだけの従来の API 連携とは異なり、MCP サーバーは構造化されたコンテキストと意味的な情報を提供し、AI アシスタントが高度なセキュリティ分析を行い、実用的なインサイトを生成できるようにします。

- **構造化されたコンテキスト:** MCP は、単なる生データの転送ではなく、DefectDojo のデータに意味的な情報を付与します
- **前処理済みデータ:** DefectDojo によって正規化・重複排除されたデータにより、LLM 側での前処理の負担がなくなります
- **ビジネスインテリジェンスとの統合:** 技術的な脆弱性データとビジネスコンテキストを組み合わせます
- **経営層にも対応できる分析:** 技術チームから経営層まで対応できるレポートを生成します
- **10 倍の複合的価値:** AI を活用した分析は、手動でのクエリよりも指数関数的に大きな価値をもたらします

> **🔑 重要:** MCP サーバーのエンドポイントは `/mcp` にありますが、すべての関数呼び出しは DefectDojo のベース URL を使用します。この分離により、脆弱性データへの安全かつ構造化されたアクセスが保証されます。

## MCP への接続

### 前提条件

- MCP サーバーが有効になっている DefectDojo インスタンス (v2.51.2 以降)
- 適切な権限を持つ有効な DefectDojo API トークン
- AI プロバイダー: Claude、ChatGPT、Gemini、またはカスタムの MCP 互換クライアント

> **⚠️ セキュリティに関する注意:** API トークンは、認証と認可に使用される非常に機密性の高い情報です。設定やスクリーンショットを共有する際は、**リクエストやレスポンスにトークンを表示しないでください**。

### 接続方法

DefectDojo MCP サーバーへの接続方法には、使用する AI インターフェースに応じて **2 通りの方法**があります。

#### 方法 1: 設定ファイル方式

**対象:** Claude Desktop、MCP Inspector、その他のデスクトップ MCP クライアント

**仕組み:**
- トークンと接続情報が設定ファイルに保存されます
- アプリケーションを起動すると自動的に接続されます
- 会話に指示を貼り付ける必要がありません
- MCP サーバーはすべての会話で常に利用可能です

**利点:** 一度設定すればどこでも使用できます。トークンがチャット履歴に残らないため、より安全です。

#### 方法 2: 手動プロンプト方式

**対象:** Claude.ai Web インターフェース、ChatGPT Web インターフェース (プラグイン使用時)、Gemini Web インターフェース

**仕組み:**
- 各会話の最初に接続手順をコピー&ペーストします
- または、Claude Project に指示を追加して自動的に含めることもできます
- AI が指示を読み取り、MCP サーバーに接続します
- 新しい会話ごとに指示が必要です

**利点:** ソフトウェアをインストールせずに Web ブラウザで動作します。

> **💡 どちらの方法を使うべきか:** 対応するデスクトップアプリがある場合は**方法 1 (設定ファイル)** を使用してください。Web ブラウザインターフェースを使用している場合は**方法 2 (手動プロンプト)** を使用してください。

### MCP サーバーの接続情報

どの方法でも、以下の基本パラメータを使用します。

| Parameter | Value | Notes |
|-----------|-------|-------|
| **トランスポートタイプ** | `Streamable HTTP` | ⚠️ SSE (Server-Sent Events) は非推奨です |
| **MCP エンドポイント URL** | `https://[YOUR-INSTANCE].defectdojo.com/mcp` | MCP 接続の確立に使用します |
| **関数用のベース URL** | `https://[YOUR-INSTANCE].defectdojo.com/` | すべてのツール関数呼び出しで使用します |
| **認証** | `Authorization: Token [YOUR_API_TOKEN]` | ⚠️「Bearer」ではなく「Token」というプレフィックスを使用してください |

## AI プロバイダー別クイックスタートガイド

<details>
<summary><h3>🖥️ Claude Desktop (方法 1: 設定ファイル)</h3></summary>

**手順 1: 設定ファイルの場所を確認する**

- **macOS:** `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Windows:** `%APPDATA%\Claude\claude_desktop_config.json`
- **Linux:** `~/.config/Claude/claude_desktop_config.json`

**手順 2: 設定ファイルを編集する**

`mcpServers` セクションに、DefectDojo インスタンスの詳細を追加または更新します。

```json
{
  "mcpServers": {
    "DefectDojo-MCP": {
      "command": "npx",
      "args": [
        "mcp-remote",
        "https://your-instance.defectdojo.com/mcp",
        "--header",
        "Authorization: Token YOUR_API_TOKEN"
      ]
    }
  }
}
```

> **⚠️ 重要:** 認証情報を含む `--header` フラグが必須です。`YOUR_API_TOKEN` を実際の DefectDojo API トークンに置き換えてください。

**手順 3: Claude Desktop を再起動する**

変更を反映させるため、Claude Desktop を閉じてから再度開いてください。

**手順 4: 接続を確認する**

新しい会話を開始し、次のように尋ねてください: `"Can you connect to DefectDojo?"`

成功すると、Claude は DefectDojo MCP サーバーのツールにアクセスできることを確認します。

> **✅ 完了!** これで DefectDojo MCP サーバーがすべての会話で利用可能になりました。指示を貼り付ける必要はありません。

</details>

<details>
<summary><h3>🌐 Claude.ai Web インターフェース (方法 2: 手動プロンプト)</h3></summary>

Claude.ai の Web インターフェースは設定ファイルに対応していません。各会話で接続手順を入力するか、Claude Project を使用する必要があります。

#### オプション A: 会話ごとに指示を貼り付ける

**手順 1: 以下の指示をコピーする**

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/ (base URL, NOT the /mcp endpoint)
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

**Do not show any of the API requests or responses.**
```

**手順 2: 新しい会話を開始する**

会話の最初に指示を貼り付けてから、セキュリティに関する質問をしてください。

**手順 3: 新しい会話ごとに繰り返す**

これらの指示は、新しい会話を始めるたびに含める必要があります。

#### オプション B: Claude Project を使用する (推奨)

**手順 1: Claude Project を作成する**

- Claude.ai で、左側のサイドバーにある「Projects」をクリックします
- 「Create Project」をクリックします
- 「DefectDojo Security Analysis」という名前を付けます

**手順 2: プロジェクトにカスタム指示を追加する**

Project Settings → Custom Instructions で、以下を貼り付けます。

```
For this project, use the DefectDojo MCP server with these parameters in ALL function calls:

- **URL:** https://your-instance.defectdojo.com/
- **Token:** YOUR_API_TOKEN
- **IMPORTANT:** DO NOT SHOW THE TOKEN IN ANY REQUESTS OR RESPONSES

The MCP server connects to https://your-instance.defectdojo.com/mcp but function calls must use the base URL.

Do not show any of the API requests or responses.
```

**手順 3: すべての DefectDojo に関する会話でこのプロジェクトを使用する**

このプロジェクト内のすべての会話が、自動的に DefectDojo MCP サーバーにアクセスできるようになります。

> **✅ 完了!** このプロジェクトで作業する際、Claude は自動的に DefectDojo MCP へのアクセス権を持ちます。

</details>

<details>
<summary><h3>💬 ChatGPT (方法 2: 手動プロンプト)</h3></summary>

> **⚠️ 注意:** ChatGPT の MCP サポートは Claude と比較して限定的です。ネイティブの MCP 連携には、ChatGPT Plus または Enterprise、および特定のプラグイン設定が必要になる場合があります。

**手順 1: MCP プラグインの利用可否を確認する**

ChatGPT で、プラグインストアに MCP または API コネクタのプラグインがあるかどうかを確認してください。MCP のサポート状況はサブスクリプションのプランによって異なります。

**手順 2: 接続手順をコピーする**

```
I need you to connect to a DefectDojo MCP server with these details:

MCP Endpoint: https://your-instance.defectdojo.com/mcp
Base URL for API calls: https://your-instance.defectdojo.com/
Authentication: Authorization header with value "Token YOUR_API_TOKEN"

Use this connection to access DefectDojo vulnerability data. The server provides tools for:
- Getting findings with severity, status, and date filters
- Accessing products, engagements, tests
- User and group management
- Analyzing security trends

Do not show the API token in responses.
```

**手順 3: 各会話の最初に貼り付ける**

DefectDojo のセキュリティ分析に関する新しい会話を始める際は、これらの指示を含めてください。

**代替方法: Custom GPT を使用する**

ChatGPT Plus をお持ちの場合は、DefectDojo の接続情報を指示に含めた Custom GPT を作成することで、繰り返し利用できるアクセス方法を用意できます。

</details>

<details>
<summary><h3>💎 Google Gemini (方法 2: 手動プロンプト)</h3></summary>

> **⚠️ 注意:** Gemini の MCP サポートは発展途上です。ネイティブ連携には制限がある場合があります。完全な機能を利用するには、MCP クライアントライブラリと組み合わせた Gemini API の使用を検討してください。

**手順 1: 接続手順をコピーする**

```
Connect to DefectDojo vulnerability management system via MCP server:

MCP Server: https://your-instance.defectdojo.com/mcp
API Base URL: https://your-instance.defectdojo.com/
Authentication: Token YOUR_API_TOKEN (use Authorization header with "Token" prefix)

Available capabilities:
- Query findings by severity (Critical, High, Medium, Low, Info)
- Filter by status (Active, Verified, False Positive, etc.)
- Filter by date ranges (Today, Past 7/30/90 days, etc.)
- Access products, engagements, tests, users, groups
- Generate security analysis and reports

Important: Do not display the authentication token in responses.
```

**手順 2: 指示とともに会話を開始する**

DefectDojo のデータを扱う際は、新しい Gemini との会話を始めるたびにこれらの指示を含めてください。

**上級ユーザー向け:**

MCP プロトコルを完全にサポートするプログラムによるアクセスには、MCP クライアントライブラリ (Python、JavaScript) と組み合わせた Gemini API の使用を検討してください。

</details>

<details>
<summary><h3>🔍 MCP Inspector (テストと検証)</h3></summary>

**ユースケース:** AI アシスタントで使用する前に、DefectDojo MCP 接続をテストし、利用可能なツールを確認し、設定を検証します。

**手順 1: MCP Inspector をインストールする**

```bash
# macOS (using Homebrew)
brew install mcp-inspector

# Or using npm (all platforms)
npm install -g @modelcontextprotocol/inspector
```

**手順 2: MCP Inspector を実行する**

```bash
mcp-inspector
```

これにより、ローカル Web サーバーが起動します (通常は `http://localhost:6274`)。

**手順 3: Web インターフェースで接続を設定する**

- **トランスポートタイプ:** `Streamable HTTP`
- **URL:** `https://your-instance.defectdojo.com/mcp`
- **接続タイプ:** `Via Proxy`
- **カスタムヘッダー:**
  - 名前: `Authorization`
  - 値: `Token YOUR_API_TOKEN`
  - **重要:** ヘッダーの横にあるトグルスイッチを有効にしてください

**手順 4: 「Connect」をクリックする**

接続すると、以下を確認できます。

- **Tools タブ:** 利用可能な 12 個のツールとそのパラメータをすべて確認できます
- **Prompts タブ:** 事前設定済みのプロンプトテンプレートを確認できます
- **Resources タブ:** 利用可能なデータリソースを確認できます

> **✅ 最適な用途:** AI アシスタントを設定する前に設定が正しく機能することを確認したり、ツールの機能を確認したり、接続の問題をトラブルシューティングしたりする場合に最適です。

</details>

---

> **✅ 接続に成功しましたか?** いずれかの方法で接続したら、AI アシスタントに次のように尋ねてテストしてください: `"How many active findings do we have in DefectDojo?"`

---

## 利用可能なツールのリファレンス

DefectDojo MCP サーバーは、脆弱性データへのアクセスと分析のために 12 個のツールを提供します。各ツールにはインテリジェントなパラメータ処理が組み込まれており、LLM による分析に最適化された構造化データを返します。

> **💡 パラメータに関する注意:** すべてのツールはオプションの `token` パラメータを受け付けます。個々の呼び出しで指定しない場合、LLM は接続設定のトークンを使用します。

---

### 🔍 検出事項分析ツール

<details>
<summary><h4>get_findings</h4></summary>

**説明:** 高度なフィルタリング機能を使用して DefectDojo から検出事項を取得します。これは脆弱性分析において最も強力で頻繁に使用されるツールです。

**パラメータ:**

**severity** (オプション)
- **型:** 文字列の配列
- **値:** `Critical`、`High`、`Medium`、`Low`、`Info`
- **例:** `["Critical", "High"]`
- **用途:** 検出事項を深刻度でフィルタリングします。複合クエリの場合は複数の値を指定できます。

**status** (オプション)
- **型:** 文字列の配列
- **値:** `Any`、`Active`、`Open`、`Verified`、`Out of Scope`、`False Positive`、`Inactive`、`Risk Accepted`、`Closed`、`Under Review`
- **例:** `["Active", "Verified"]`
- **用途:** 検出事項を現在のステータスでフィルタリングします。現在のリスク評価には `Active` を使用してください。

**date** (オプション)
- **型:** 単一の文字列値を持つ配列
- **値:** `0 - Any date`、`1 - Today`、`2 - Past 7 days`、`3 - Past 30 days`、`4 - Past 90 days`、`5 - Current month`、`6 - Current year`、`7 - Past year`
- **例:** `["3 - Past 30 days"]`
- **用途:** 検出事項を検出日でフィルタリングします。指定できる値は 1 つだけです。

**limit** (オプション)
- **型:** 数値
- **デフォルト:** 100
- **範囲:** 1〜100
- **用途:** 返す検出事項の件数です。件数のみが必要な場合は 1 に設定し、レスポンスの count プロパティを使用してください。

**offset** (オプション)
- **型:** 数値
- **デフォルト:** 0
- **用途:** 追加の結果を取得するためのページネーションオフセットです。

> **💡 ベストプラクティス:** リスク評価のクエリでは、過去のデータではなく現在未解決の脆弱性に焦点を当てるため、常に `status: ["Active"]` を使用してください。

**クエリ例:**

**ユーザーの質問:** 「過去 30 日間の Critical および High 深刻度のアクティブな検出事項をすべて見せてください」

**LLM の呼び出し:**
```
get_findings({
  severity: ["Critical", "High"],
  status: ["Active"],
  date: ["3 - Past 30 days"],
  limit: 100
})
```

</details>

<details>
<summary><h4>get_finding_by_id</h4></summary>

**説明:** 一意の識別子を使用して、特定の検出事項の詳細情報を取得します。

**パラメータ:**

**finding_id** (必須)
- **型:** 数値
- **最小値:** 1
- **用途:** 取得する検出事項の一意の ID です。

**クエリ例:**

**ユーザーの質問:** 「検出事項 #1234 の詳細を取得してください」

**LLM の呼び出し:** `get_finding_by_id({ finding_id: 1234 })`

</details>

---

### 📦 製品・エンゲージメントツール

<details>
<summary><h4>get_products</h4></summary>

**説明:** DefectDojo からすべての製品を取得します。製品は、テスト対象のアプリケーション、サービス、またはシステムを表します。

**パラメータ:**

**limit** (オプション)
- **デフォルト:** 100
- **用途:** 返す製品の最大数です。

**offset** (オプション)
- **デフォルト:** 0
- **用途:** ページネーションオフセットです。

</details>

<details>
<summary><h4>get_product_types</h4></summary>

**説明:** DefectDojo から製品タイプのカテゴリを取得します。製品タイプは、製品を論理的なグループに整理するのに役立ちます。

**パラメータ:** `get_products` と同じ

</details>

<details>
<summary><h4>get_engagements</h4></summary>

**説明:** セキュリティテストのエンゲージメントを取得します。エンゲージメントは、製品に対する特定のテスト活動や期間を表します。

**パラメータ:** `get_products` と同じ

</details>

<details>
<summary><h4>get_tests</h4></summary>

**説明:** DefectDojo からセキュリティテストを取得します。テストには、特定のセキュリティツールまたは手動テストによるスキャン結果が含まれます。

**パラメータ:** `get_products` と同じ

</details>

---

### 👥 ユーザー・アクセス管理ツール

<details>
<summary><h4>get_users</h4></summary>

**説明:** ステークホルダー分析と責任範囲のマッピングのために、DefectDojo からすべてのユーザーを取得します。

**パラメータ:**

**limit** (オプション)
- **デフォルト:** 100

**offset** (オプション)
- **デフォルト:** 0

</details>

<details>
<summary><h4>get_user_by_id</h4></summary>

**説明:** 特定のユーザーの詳細情報を取得します。

**パラメータ:**

**user_id** (必須)
- **型:** 数値
- **最小値:** 1

</details>

<details>
<summary><h4>get_groups</h4></summary>

**説明:** 組織構造の分析と権限のマッピングのために、ユーザーグループを取得します。

**パラメータ:** `get_users` と同じ

</details>

<details>
<summary><h4>get_group_by_id</h4></summary>

**説明:** 特定のグループの詳細情報を取得します。

**パラメータ:**

**group_id** (必須)
- **型:** 数値
- **最小値:** 1

</details>

<details>
<summary><h4>get_dojo_group_members</h4></summary>

**説明:** チーム分析のために、特定のグループのすべてのメンバーを取得します。

**パラメータ:**

**group_id** (必須)
- **型:** 数値
- **最小値:** 1

**limit** (オプション)
- **デフォルト:** 100

**offset** (オプション)
- **デフォルト:** 0

</details>

<details>
<summary><h4>get_roles</h4></summary>

**説明:** 権限構造を理解するために、DefectDojo からロールの定義を取得します。

**パラメータ:** `get_users` と同じ

</details>

---

## 事前設定済みのプロンプト

DefectDojo MCP サーバーには、一般的な分析シナリオのベストプラクティスを示す事前設定済みのプロンプトが含まれています。これらのプロンプトは、AI アシスタントから直接呼び出すことができます。

### 🛡️ SAST レビューレポート

**目的:** DefectDojo のデータに基づいて、SAST (Static Application Security Testing) ツールの有効性を評価する包括的なレポートを作成します。

**生成される分析の内容:**

- ツールおよび脆弱性タイプ別の誤検知率
- 深刻度別の平均修復時間
- 複数回出現する重大な脆弱性 (重複排除の不備)
- 開発チームのパフォーマンス比較
- ツール設定改善の推奨事項
- 繰り返し発生する脆弱性パターンから特定されたトレーニングのギャップ
- 現行のツールと推奨ツールアプローチのコスト分析

**出力形式:** セキュリティツールの予算要求を正当化するのに適した、HTML 形式の技術評価レポート。

### 📊 セキュリティランドスケープレポート

**目的:** DefectDojo のデータに基づいて、四半期の取締役会に適したセキュリティランドスケープの概要を示すダッシュボード形式のレポートを作成します。

**生成される分析の内容:**

- 過去 90 日間の脆弱性トレンド
- Critical/High 深刻度の検出事項が最も多い開発チーム
- 製品および製品タイプ別のリスクエクスポージャー
- 早急な対応が必要な上位 5 つの CWE カテゴリ
- 費用対効果分析を伴う具体的な修復アクション
- セキュリティ態勢を改善するための 6 か月間のロードマップ

**出力形式:** ビジュアル要素、統計カード、ビジネスリスクに焦点を当てた、経営層向けの HTML レポート。

> **💡 プロンプトの使用方法:** プロンプトを呼び出すには、AI アシスタントに「Create a SAST Review Report」または「Generate a Security Landscape Report using DefectDojo data」のように尋ねるだけです。

---

## ユースケース例

### ユースケース 1: 経営層向けセキュリティダッシュボード

**シナリオ:** CISO が取締役会でのプレゼンテーション用に四半期のセキュリティ指標を必要としている

**ユーザープロンプト:**

```
"Create an executive security dashboard for our Q4 board meeting showing:
- Total vulnerability counts by severity
- Trends over the past 90 days  
- Which products have the highest risk exposure
- Top 5 vulnerability categories needing attention
- Specific remediation recommendations with ROI
- A 6-month roadmap for improving our security posture"
```

**裏側で行われる処理:**

1. `get_findings` - アクティブな検出事項の総数を取得
2. `get_findings` - Critical および High 深刻度の分析
3. `get_findings` - 90 日間のトレンドデータ
4. `get_products` - 製品ごとの脆弱性分布
5. `get_engagements` - 最近のテスト活動

**生成される出力:** 脆弱性トレンド、製品別リスクエクスポージャー、上位 CWE カテゴリ、ROI を伴う具体的な修復アクション、6 か月間のセキュリティロードマップを含む、経営層向けの HTML レポート。

---

### ユースケース 2: 開発チームのパフォーマンス分析

**シナリオ:** エンジニアリングマネージャーが、どのチームに追加のセキュリティトレーニングが必要かを把握したい

**ユーザープロンプト:**

```
"Which development teams have the most security findings? What types of vulnerabilities 
are they creating repeatedly? Based on this analysis, recommend specific security 
training programs for each team."
```

**裏側で行われる処理:**

1. `get_findings` - すべてのアクティブな検出事項
2. `get_products` - 検出事項を製品/チームに紐付け
3. `get_groups` - チームの組織構造
4. `get_users` - 個々の開発者の責任範囲

**提供される分析:** チーム別にグループ化された検出事項、繰り返されるミスを示す CWE パターン分析、トレーニングギャップの特定、および対象を絞ったセキュリティトレーニングプログラムの推奨事項。

---

### ユースケース 3: ツール有効性評価

**シナリオ:** セキュリティチームが現行の SAST ツールの ROI を評価している

**ユーザープロンプト:**

```
"Analyze the effectiveness of our SAST tools. Show me false positive rates, 
mean time to remediation, which tools find the most valuable vulnerabilities, 
and recommend configuration improvements or alternative tools."
```

**裏側で行われる処理:**

1. `get_tests` - ツール別のすべてのセキュリティテスト
2. `get_findings` - 誤検知の分析
3. `get_findings` - ツール別のアクティブな検出事項
4. `get_findings` - 修復パターンのためのクローズ済み検出事項

**提供される分析:** ツール別の誤検知率、深刻度別の平均修復時間、重複検出事項の分析、ツール設定の推奨事項、トレーニングギャップ、および代替ツールアプローチの費用対効果分析。

---

### ユースケース 4: コンプライアンスレポート

**シナリオ:** 脆弱性管理のエビデンスが必要な SOC 2 監査への準備

**ユーザープロンプト:**

```
"Generate a SOC 2 compliance report showing our vulnerability management processes, 
including discovery and remediation procedures, SLA compliance, continuous monitoring 
evidence, and accountability documentation."
```

**裏側で行われる処理:**

1. `get_findings` - Critical/High のアクティブな検出事項
2. `get_findings` - 年初来の検出トレンド
3. `get_engagements` - テストの頻度とカバレッジ
4. `get_users` - 修復の責任範囲

**提供される分析:** 脆弱性の検出・修復プロセス、SLA 遵守状況の追跡、継続的モニタリングのエビデンス、責任範囲の文書化、および監査前に修復が必要なギャップ。

---

### ユースケース 5: リスクの優先順位付け

**シナリオ:** セキュリティチームのリソースが限られており、修復作業の優先順位付けが必要

**ユーザープロンプト:**

```
"What are the highest priority vulnerabilities we should fix first? Consider severity, 
how long they've been open, exploitability, and business impact. Give me a prioritized 
remediation roadmap with effort estimates."
```

**裏側で行われる処理:**

1. `get_findings` - Critical/High のアクティブな検出事項
2. `get_products` - ビジネス上の重要度に関するコンテキスト
3. エージング指標の分析 (検出からの経過日数)
4. EPSS スコア (悪用予測) との相互参照

**提供される分析:** 深刻度、経過期間、悪用可能性、ビジネスへの影響を組み合わせたリスクランク付けされた脆弱性リスト。工数見積もりと期待されるリスク低減効果を伴う具体的な修復ロードマップ。

---


## ベストプラクティスとクエリパターン

### 段階的なデータ読み込み戦略

AI アシスタントは、以下のデータ読み込みパターンに自動的に従うことでパフォーマンスを最適化します。

**1. サマリーデータから始める**

詳細な分析を依頼する前に、件数を尋ねてください。

```
"How many critical and high severity findings do we have?"
```

AI アシスタントは、`limit: 1` を指定した `get_findings` ツールを使用して、件数だけを効率的に取得します。

**2. 戦略的なページネーションを使用する**

大規模なデータセットの場合、AI アシスタントは自動的に結果をページ送りします。

```
"Analyze all our active vulnerabilities"
```

AI は必要に応じて複数回の呼び出しを行い、妥当な上限値から始めて必要に応じて増やしていきます。

**3. 効率的なデータの再利用**

冗長なクエリを避けるため、関連する質問を続けて行ってください。

```
"Show me all critical findings, then tell me which CWE categories they fall into"
```

AI は、最初のクエリで取得した検出事項データを CWE 分析に再利用します。

### スマートなフィルタリング戦略

DefectDojo の強力なフィルタリング機能を活用できるよう、プロンプトを工夫してください。

#### 深刻度に基づくクエリ

**ユーザープロンプト:**
```
"Show me all Critical and High severity issues that need immediate attention"
```

**裏側の処理:** AI は severity と status のフィルタを指定して `get_findings` を使用します

#### 期間に基づくクエリ

**ユーザープロンプト:**
```
"What new vulnerabilities have been discovered in the past 30 days?"
```

**裏側の処理:** AI は「Past 30 days」の date フィルタを active ステータスとともに適用します

#### 複合フィルタリング

**ユーザープロンプト:**
```
"Give me a risk assessment of all critical and high active findings from the past 90 days"
```

**裏側の処理:** AI は severity、status、date のフィルタを組み合わせて包括的な分析を行います

### 相互参照分析

AI アシスタントは、検出事項を組織的なコンテキストに自動的に紐付けます。包括的な質問をするだけで構いません。

**ユーザープロンプト:**
```
"Which products have the most critical vulnerabilities and who is responsible for fixing them?"
```

**裏側の処理:** AI は、検出事項 → テスト → エンゲージメント → 製品 → ユーザー/グループ を紐付けて、完全なコンテキストを構築します

### 脆弱性インテリジェンス分析

**CWE パターン分析**

**ユーザープロンプト:**
```
"What are the most common vulnerability types in our codebase and which teams are creating them?"
```

AI は検出事項を CWE でグループ化し、繰り返し発生するパターン、トレーニングの必要性、アーキテクチャ上の問題を特定します。

**エージング指標**

**ユーザープロンプト:**
```
"How long have our critical vulnerabilities been open? Which ones are overdue for remediation?"
```

AI は検出からの経過時間を計算し、SLA のしきい値を超えている検出事項にフラグを立てます。

**脆弱性密度**

**ユーザープロンプト:**
```
"Which products have the highest vulnerability density and represent the greatest risk?"
```

AI は製品ごとの検出事項数を計算し、深刻度と件数を組み合わせたリスクスコアを生成します。

### レポート品質向上のための基準

#### 必ず含めるべき項目

- **具体的な指標:** 一般論ではなく、深刻度別の実際の件数
- **CWE 分析:** 説明付きの上位脆弱性タイプ
- **エージングデータ:** 脆弱性がどのくらいの期間未解決であるか
- **実行可能な推奨事項:** 次に何をすべきか、そのタイムラインとともに
- **ROI 計算:** 対応策の予想コストと効果
- **成功指標:** 改善をどのように測定するか

#### 業界標準との照らし合わせ

DefectDojo の検出事項を業界フレームワークと比較します。

- **OWASP Top 10:** Web アプリケーションセキュリティリスク
- **SANS Top 25:** 最も危険なソフトウェアの弱点
- **CWE Top 25:** 最も一般的で影響の大きい弱点
- **コンプライアンスフレームワーク:** SOC 2、ISO 27001、NIST CSF

## MCP のトラブルシューティング

### 診断チェックリスト

接続の問題が発生した場合は、以下の項目を確認してください。

- ✅ トランスポートタイプが **Streamable HTTP** になっている (SSE ではない)
- ✅ MCP エンドポイント URL が正しい: `https://[instance].defectdojo.com/mcp`
- ✅ Authorization ヘッダーが有効になっている (トグルが ON)
- ✅ トークンの形式に `Token` プレフィックスが含まれている
- ✅ トークンが有効で、適切な権限を持っている
- ✅ DefectDojo インスタンスにアクセスできる (Web UI からログインできる)
- ✅ ネットワーク接続が HTTPS 接続を許可している

### よくある接続の問題

#### ❌「Connection Error - Check if your MCP server is running」

**原因:** 非推奨の SSE (Server-Sent Events) トランスポートタイプを使用している

**解決策:** トランスポートタイプを `Streamable HTTP` に変更してください

**理由:** DefectDojo MCP サーバーは最新の Streamable HTTP プロトコルを使用しています。SSE は非推奨であり、サポートされていません。

---

#### ❌「Authentication Failed」または「401 Unauthorized」

**原因:** 認証ヘッダーの形式が正しくない、またはトークンが無効

**解決策:**

1. ヘッダーの値が (`Bearer` ではなく) `Token` プレフィックスを使用していることを確認してください
   ```
   ✅ Correct: Token 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ❌ Wrong: Bearer 7c6cc2xxxxxxxxxxxxxxxxxxxx87fcf72ec2b3fb
   ```

2. Authorization ヘッダーのトグルが有効 (ON) になっていることを確認してください
3. DefectDojo でトークンが引き続き有効であることを確認してください (Admin → API Tokens)
4. トークンに読み取りアクセスのための適切な権限があることを確認してください

---

#### ❌ ツールが空の結果を返す

**考えられる原因:**

- フィルタが厳しすぎる (条件に一致するデータがない)
- DefectDojo インスタンスに、要求されたカテゴリのデータがない
- トークンの権限が不足している

**解決策:**

1. まず、より範囲の広いクエリを試してください: `get_findings({ limit: 10 })`
2. フィルタを 1 つずつ削除して、制限の原因になっているフィルタを特定してください
3. DefectDojo でトークンの権限を確認してください
4. DefectDojo の UI で直接データが存在するかを確認してください

---

#### ⚠️ レスポンスが遅い

**原因:** 一度に大量のデータを要求している

**解決策:**

- `limit` パラメータを小さくする (まず 50〜100 から始めてください)
- より具体的なフィルタを使用して結果セットのサイズを減らす
- 段階的な読み込みを使用する: まず件数を取得し、その後詳細を取得する
- 大規模なデータセットにはページネーションを実装する

---
