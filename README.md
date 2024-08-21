# Rust プロジェクトのデバッグ設定

この README では、Visual Studio Code (VSCode) を使用してこの Rust プロジェクトをデバッグするための設定方法を説明します。

## 前提条件

- Visual Studio Code がインストールされていること
- Rust と Cargo がインストールされていること
- VSCode の "CodeLLDB" 拡張機能がインストールされていること

## デバッグ設定

1. プロジェクトのルートディレクトリに `.vscode` フォルダを作成します（存在しない場合）。

2. `.vscode` フォルダ内に `launch.json` ファイルを作成し、以下の内容を貼り付けます：

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug executable",
      "cargo": {
        "args": ["build"],
        "filter": {
          "kind": "bin"
        }
      },
      "args": [],
      "cwd": "${workspaceFolder}"
    }
  ]
}
```

## 設定の説明

- `type`: "lldb" を使用してデバッグします。これは CodeLLDB 拡張機能によって提供されます。
- `request`: "launch" は新しいプロセスを起動してデバッグすることを意味します。
- `name`: デバッグ設定の名前です。VSCode のデバッグビューに表示されます。
- `cargo`: Cargo コマンドの設定です。
  - `args`: Cargo に渡す引数です。ここでは `build` コマンドを使用しています。
  - `filter`: ビルドする項目を "bin"（実行可能ファイル）に限定しています。
- `args`: プログラムに渡す引数です。必要に応じて追加してください。
- `cwd`: プログラムの作業ディレクトリです。`${workspaceFolder}` はプロジェクトのルートディレクトリを指します。

## デバッグの開始方法

1. VSCode でプロジェクトを開きます。
2. デバッグしたい Rust ファイルを開きます。
3. ブレークポイントを設定します。
4. F5 キーを押すか、サイドバーのデバッグアイコンをクリックしてデバッグを開始します。
5. "Debug executable" 設定を選択します。

これで、プログラムがブレークポイントで停止し、変数の確認やステップ実行などのデバッグ作業が行えるようになります。

## 注意事項

- この設定は基本的なものです。プロジェクトの特性に応じて `launch.json` を調整する必要があるかもしれません。
- 環境変数や追加の引数が必要な場合は、適宜 `launch.json` に追加してください。
- チーム開発の場合、各開発者の環境に合わせて `launch.json` を調整する必要があるかもしれません。

## ECR にデプロイ

- Docker Image を Build
  - `docker build --platform=linux/amd64 -t rs-subscribe-auth .`
