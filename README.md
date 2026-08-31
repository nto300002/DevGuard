# DevGuard

DevGuardは、`git commit` や `git push` の前に危険な変更を検出し、開発者が一度立ち止まって確認できるようにする TypeScript + Node.js 製のCLIツールです。

AIコーディングやADHD傾向のある開発フローでは、コード品質そのものよりも「確認漏れ」が問題になりがちです。DevGuardは、commit粒度の粗さ、debug logの消し忘れ、環境変数やSecretsの確認漏れ、Issueスコープ外のDB/config変更、レビュー前確認の曖昧さをGit操作前に可視化します。

## コンセプト

DevGuardは、AI時代のpre-commit / pre-push型セルフレビュー支援ツールです。

Copilotのようにコードを書くツールではなく、レビュー担当者を置き換えるものでもありません。Git操作の直前に差分を解析し、「何を変更したか」「何が危険か」「人間がまだ確認すべきことは何か」を説明できる状態に整えるためのガードです。

## MVPスコープ

MVPでは以下に注力します。

- 任意のサブディレクトリからのGit root検出
- Git root相対パスへの正規化
- `.devguard.yml` の読み込みとdefault config
- `devguard doctor`
- `devguard check --staged`
- `devguard security-check`
- `devguard push-check`
- `defaultBranch...HEAD` 差分解析
- keyword rule
- 厳しめのdebug log検出
- reason必須の抑制コメント
- 環境変数 / Secrets の整合性チェック
- Issueスコープチェック
- 手動テスト確認todo
- AIエージェント向け確認ブロック
- `pre-commit` / `pre-push` hook導入

MVPでは、GitHub OAuth、GitHub Secretsの実在確認、GitHub Issue本文の取得、Web UI、VS Code拡張、自動修正、AI生成コードの正しさ判定は扱いません。

## 対象技術

初期preset:

- TypeScript
- Python
- PHP
- Next.js
- FastAPI

その他の技術スタックもdefault keyword databaseには含まれる場合がありますが、MVPの正式presetとしては有効化しません。

## コマンド

```bash
devguard doctor
devguard init
devguard check --staged
devguard check --staged-diff
devguard check --worktree-diff
devguard check --all-diff
devguard security-check
devguard security-check --json
devguard security-check --mode general
devguard security-check --write-baseline
devguard push-check
devguard install-hooks
devguard install-hooks --include-submodules
```

## インストール

npm公開版をグローバルインストールする場合:

```bash
npm install -g @nto300002/devguard
```

インストール後は `devguard` コマンドを使えます。

```bash
devguard --help
devguard doctor
```

一度だけ実行する場合:

```bash
npx --yes --package=@nto300002/devguard devguard doctor
npx --yes --package=@nto300002/devguard devguard check --staged
npx --yes --package=@nto300002/devguard devguard check --staged-diff
npx --yes --package=@nto300002/devguard devguard check --worktree-diff
npx --yes --package=@nto300002/devguard devguard check --all-diff
npx --yes --package=@nto300002/devguard devguard security-check
npx --yes --package=@nto300002/devguard devguard security-check --mode general
```

GitHub Releaseからtarballをダウンロードして導入する場合:

```bash
npm install -g ./nto300002-devguard-0.1.0.tgz
```

## ローカルインストール

このリポジトリからローカル開発用に使う場合:

```bash
npm install
npm run build
npm link
```

link後は、ローカル環境で `devguard` コマンドを使えます。

```bash
devguard --help
devguard doctor
```

linkを解除する場合:

```bash
npm unlink -g @nto300002/devguard
```

## ローカルでの使い方

staged差分をcommit前に確認します。

```bash
git add <files>
devguard check --staged
```

staged差分のファイル数・変更行数を強めに意識して確認する場合:

```bash
devguard check --staged-diff
```

まだ `git add` していない作業ツリー差分を確認する場合:

```bash
devguard check --worktree-diff
```

staged / unstaged / untracked をまとめて確認する場合:

```bash
devguard check --all-diff
```

差分確認コマンドの使い分け:

- `check --staged`: commit直前のstaged差分を確認
- `check --staged-diff`: staged差分に加えてPRサイズ目安を強調
- `check --worktree-diff`: `git add` 前のunstaged / untracked差分を確認
- `check --all-diff`: HEADから見たstaged / unstaged / untracked差分をまとめて確認

差分サイズの目安:

- 1-5ファイル / 変更150行以下: 小さくまとまったPR
- 6-10ファイル または 変更151-300行: PR分割を検討
- 11ファイル以上 または 変更301行以上: 小さなPRに分割

branch全体をpush前に確認します。

```bash
devguard push-check --agent-block
```

現在のリポジトリにGit hookを導入します。

```bash
devguard install-hooks
```

初期化済みサブモジュールにもまとめてGit hookを導入する場合:

```bash
devguard install-hooks --include-submodules
```

サブモジュールやGit worktreeでも正しいhook配置先を使うため、DevGuardは `git rev-parse --git-path hooks` でhookディレクトリを解決します。

導入されるhookは以下を実行します。

- `pre-commit`: `npx --yes --package=@nto300002/devguard devguard check --staged`
- `pre-push`: `npx --yes --package=@nto300002/devguard devguard push-check --agent-block`

packageを公開せずにローカル開発版でhookを試す場合は、`DEVGUARD_BIN` で実行コマンドを差し替えられます。

```bash
DEVGUARD_BIN="node /absolute/path/to/DevGuard/dist/cli.js" git commit -m "test"
```

## 現在のセキュリティ検出

リポジトリ全体を確認する場合は、以下を実行します。

```bash
devguard security-check
```

検出モードは次の2種類です。

- `security-flow`: Secret、リクエスト入力、例外情報などがログ・URL・レスポンス・ストレージ・デプロイ設定へ流れる経路を検出します。
- `general-vulnerability`: SQL Injection、XSS、Command Injection、Unsafe Deserialization、SSRF、Path Traversalの脆弱性候補を検出します。

一般脆弱性候補だけを確認する場合は、以下を実行します。検出は脆弱性の確定ではなく、ファイル・行番号・CWE・OWASP分類・confidence・対応方法を含む候補報告です。

```bash
devguard security-check --mode general
devguard security-check --mode general --json
```

一般脆弱性の代表ルールは、TypeScript / Python / PHP / Dartの入力と危険APIの組み合わせを対象にします。parameterized query、固定コマンドなど安全な実装は検出対象から除外しますが、最終的なレビューとテストは必要です。

対象言語に応じて、TypeScript / Python / PHPでは構文木を利用した検査、Dartでは安全な範囲のソース検査、YAML / Dockerfileでは構造検査を行います。High検出がある場合は終了コード1になります。

依存関係・仮想環境・キャッシュ・生成物は標準で検査対象から除外します。例: `node_modules`、`vendor`、`.venv`、`venv`、`env`、`.dart_tool`、`build`、`dist`、`.next`、`coverage`。

CIで集計する場合はJSON形式を利用できます。検出内容、解析不能ファイル、severity別・ruleId別の集計を出力します。

```bash
devguard security-check --json > devguard-security.json
```

既存検出をベースラインへ登録する場合は、設定した`baselinePath`へ書き出します。未設定の場合は`.devguard-security-baseline.json`が使用されます。

```bash
devguard security-check --write-baseline
git add .devguard.yml .devguard-security-baseline.json
```

既存コードを段階導入する場合は、リポジトリ直下の `.devguard.yml` で対象外パスと期限付き例外を明示します。

```yaml
securityCheck:
  enabled: true
  failOnUnparseable: false
  baselinePath: .devguard-security-baseline.json
  excludePaths:
    - tests/**
    - e2e/**
  allowlist:
    - ruleId: secret-to-log
      filePath: legacy/**
      reason: "既存連携の移行完了まで監視のみ"
      owner: security-team
      expires: "2026-12-31"
      issue: "#123"
```

allowlistには理由・所有者・期限・追跡Issueを必須とし、期限切れの例外は自動的に抑制解除されます。検査結果にはSecretの実値を出力しません。

既存検出をベースラインとして扱う場合は、`baselinePath` に次の形式のJSONを指定します。ベースラインに記録された検出は表示されますが、新規検出としてはブロックされません。

```json
{
  "findingIds": [
    "secret-to-log:legacy/auth.py:42"
  ]
}
```

DevGuardはdefault keyword databaseで以下のセキュリティ関連パターンを検出します。

- `console.log(user)` のような変数debug log
- `API_KEY`、`TOKEN`、`PASSWORD`、`DATABASE_URL`、`OPENAI_API_KEY` などのsecretらしい名前
- `${{ secrets.STRIPE_SECRET_KEY }}` のようなGitHub Actions secret参照
- `eval(`、`innerHTML`、`dangerouslySetInnerHTML` などの危険API
- `browser-storage-risk` ruleによる `localStorage` / `sessionStorage` 使用

## Hookの挙動

`pre-commit` では以下を実行します。

```bash
npx --yes --package=@nto300002/devguard devguard check --staged
```

`pre-push` では以下を実行します。

```bash
npx --yes --package=@nto300002/devguard devguard push-check --agent-block
```

High riskのcommit findingがある場合はcommitを停止します。High riskのpush findingがある場合はpushを停止します。Security FlowのHigh検出も同様に停止対象です。

## Human-on-the-Loop開発フロー

DevGuardはAIエージェントや自動化された開発フローを置き換えるのではなく、人間が判断すべき高リスク変更だけを止める安全弁として利用します。通常の実装・テスト・低リスク変更は自動で進め、新規High検出、認証・認可、Secrets、公開API、DB、デプロイ設定の変更で人間の確認を要求します。

推奨フロー:

1. AIエージェントがIssueを分析し、実装とテストを作成する
2. `pre-commit`で変更行を検査する
3. `pre-push`でブランチ差分と新規Findingを検査する
4. CIでDevGuard、依存関係、Secret、CodeQL、テストを実行する
5. Lowは自動通過、Mediumは警告、Highは人間の確認または修正完了まで停止する
6. 承認された例外は理由・owner・期限・Issueを付けてallowlistまたはbaselineへ記録する
7. StagingでAPI/E2E/DASTを実行し、結果を確認してから本番へ進める

自動化の判断基準:

| 状態 | 自動処理 | 人間の関与 |
| --- | --- | --- |
| Low / confidence high | commit・pushを許可 | 原則不要 |
| Medium | 警告して継続 | Pull Requestで確認 |
| 新規High / confidence high | commit・push・mergeを停止 | 必須 |
| High / confidence medium | 修正案とテスト案を生成 | 修正内容を承認 |
| 解析不能 | 設定に応じて警告または停止 | 対象コードを確認 |

人間の確認対象は、認証・認可、個人情報・決済、外部公開API、DB migration、ファイルアップロード、Secret・権限設定、本番デプロイ、自動修正の適用です。検出結果は脆弱性の確定ではなく候補として扱い、最終判断はコードレビューと実行時テストで行います。

### セキュリティ拡張ロードマップ

Issueは、検出・CI連携・依存関係・人間承認を独立して実装できる単位に分けます。

- SARIF出力とGitHub Code Scanning連携
- npm / pip / Composer / pub依存関係の脆弱性検査
- Secret形式・高エントロピー値・Git履歴の検査
- Finding fingerprintとbaselineのライフサイクル管理
- リスクベースのHuman GateとPull Requestコメント
- 自動修正候補と修正後再スキャン
- StagingのAPI/E2E/DAST結果との統合

基準として、Webアプリケーションの検証項目は [OWASP ASVS](https://owasp.org/www-project-application-security-verification-standard/) を参照し、開発プロセス全体の予防・検出・修正・再発防止は [NIST SSDF](https://csrc.nist.gov/projects/ssdf) に沿って段階的に整備します。

## ドキュメント

- [要件定義](docs/requirements.md)
- [詳細定義](docs/detail-design.md)

## MVP完成条件

TypeScript、Python、PHP、Next.js、FastAPIのプロジェクトで、危険なlog、環境変数 / Secrets追加、スコープ外DB/config変更をcommit前・push前に安定して検出できることをMVP完成条件とします。
