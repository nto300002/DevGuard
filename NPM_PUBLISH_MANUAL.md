# agent-safecheck npm公開マニュアル

この手順は、リポジトリroot（`package.json`があるディレクトリ）で実行する。

## 1. 公開前の確認

```sh
cd /path/to/DevGuard
npm install
npm test
npm run typecheck
npm run build
npm pack --dry-run
```

`npm pack --dry-run`で、`dist/`、`package.json`、READMEなど必要なファイルだけが含まれていることを確認する。秘密情報、`.env`、テスト用の機密データを含めない。

公開対象の現在バージョンを確認する。

```sh
node -p "require('./package.json').version"
npm view agent-safecheck version
```

## 2. npm認証

```sh
npm config set registry https://registry.npmjs.org/
npm login
npm whoami
```

CIや自動化では、パスワードをコマンドラインに直接書かず、npmのアクセストークンを安全なSecretとして設定する。

## 3. バージョン更新

npmでは、公開済みバージョンを上書きできない。`npm view agent-safecheck version`で確認した番号より大きいバージョンへ更新する。

```sh
npm version patch --no-git-tag-version
```

機能追加や破壊的変更の場合は、次のいずれかを使用する。

```sh
npm version minor --no-git-tag-version
npm version major --no-git-tag-version
```

更新後に`package.json`と`package-lock.json`のバージョンが一致していることを確認する。

```sh
node -p "require('./package.json').version"
node -p "require('./package-lock.json').version"
```

## 4. 公開

```sh
npm publish --access public
```

公開後、レジストリから確認する。

```sh
npm view agent-safecheck version
npm view agent-safecheck dist.tarball
```

利用側では、公開したバージョンを明示して動作確認する。

```sh
npx --yes --package=agent-safecheck@<公開バージョン> safecheck --help
npx --yes --package=agent-safecheck@<公開バージョン> safecheck check --staged
```

## 5. よくあるエラー

### `You cannot publish over the previously published versions`

同じバージョンは再公開できない。`npm version patch --no-git-tag-version`などでバージョンを上げ、`package.json`と`package-lock.json`を確認してから再実行する。

### `E404 ... PUT ...` または `could not be found or you do not have permission`

次を順番に確認する。

```sh
npm config get registry
npm whoami
npm access ls-packages
npm view agent-safecheck
```

registryがnpm公式でない場合は、次を実行する。

```sh
npm config set registry https://registry.npmjs.org/
```

それでも失敗する場合は、ログイン中のnpmアカウントに`agent-safecheck`の公開権限があるか確認する。パッケージ名の取り違え、組織名・scopeの不一致、期限切れトークンも確認する。

### `ENEEDAUTH` / `401 Unauthorized`

```sh
npm logout
npm login
npm whoami
```

2要素認証が有効なアカウントでは、npmの案内に従ってOTPを入力する。トークン利用時は公開権限を持つトークンを使用する。

## 6. 公開後のチェックリスト

- [ ] `npm view agent-safecheck version`が期待する新しい番号になっている
- [ ] `npx --yes --package=agent-safecheck@<version> safecheck --help`が動作する
- [ ] `check --staged`、`security-check`、hookが公開版で動作する
- [ ] workflow allowlistを使う場合、利用側の`.devguard.yml`に`path`、`job_id`、`step_name`、`env_key`、`secret_name`、`reason`、`owner`、`expires_on`が設定されている
- [ ] 公開したバージョン、コミット、変更内容をリリース記録へ残している

公開済みバージョンの削除や上書きで問題を解決しようとしてはいけない。npmの公開バージョンは不変として扱い、必ず次のバージョンを公開する。
