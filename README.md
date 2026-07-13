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

MVPでは、GitHub OAuth、GitHub Secretsの実在確認、GitHub Issue本文の取得、Web UI、VS Code拡張、AST解析、自動修正、AI生成コードの正しさ判定は扱いません。

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
devguard push-check
devguard install-hooks
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
npm unlink -g devguard
```

## ローカルでの使い方

staged差分をcommit前に確認します。

```bash
git add <files>
devguard check --staged
```

branch全体をpush前に確認します。

```bash
devguard push-check --agent-block
```

現在のリポジトリにGit hookを導入します。

```bash
devguard install-hooks
```

導入されるhookは以下を実行します。

- `pre-commit`: `npx devguard check --staged`
- `pre-push`: `npx devguard push-check --agent-block`

packageを公開せずにローカル開発版でhookを試す場合は、`DEVGUARD_BIN` で実行コマンドを差し替えられます。

```bash
DEVGUARD_BIN="node /absolute/path/to/DevGuard/dist/cli.js" git commit -m "test"
```

## 現在のセキュリティ検出

DevGuardはdefault keyword databaseで以下のセキュリティ関連パターンを検出します。

- `console.log(user)` のような変数debug log
- `API_KEY`、`TOKEN`、`PASSWORD`、`DATABASE_URL`、`OPENAI_API_KEY` などのsecretらしい名前
- `${{ secrets.STRIPE_SECRET_KEY }}` のようなGitHub Actions secret参照
- `eval(`、`innerHTML`、`dangerouslySetInnerHTML` などの危険API
- `browser-storage-risk` ruleによる `localStorage` / `sessionStorage` 使用

## Hookの挙動

`pre-commit` では以下を実行します。

```bash
npx devguard check --staged
```

`pre-push` では以下を実行します。

```bash
npx devguard push-check --agent-block
```

High riskのcommit findingがある場合はcommitを停止します。High riskのpush findingがある場合はpushを停止します。

## ドキュメント

- [要件定義](docs/requirements.md)
- [詳細定義](docs/detail-design.md)

## MVP完成条件

TypeScript、Python、PHP、Next.js、FastAPIのプロジェクトで、危険なlog、環境変数 / Secrets追加、スコープ外DB/config変更をcommit前・push前に安定して検出できることをMVP完成条件とします。
