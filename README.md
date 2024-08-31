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

<br/>
<br/>
<br/>

# ECR にデプロイ
このプロジェクトのDockerイメージをAmazon Elastic Container Registry (ECR)にプッシュするには、以下の手順に従ってください。

### 前提条件

- AWSアカウントとECRリポジトリが設定されていること
- AWS CLIがインストールされ、適切に設定されていること
- Dockerがインストールされていること

### 手順

1. AWSアカウントにログインします：

    ```sh
    aws ecr get-login-password --region <your-region> | docker login --username AWS --password-stdin <your-account-id>.dkr.ecr.<your-region>.amazonaws.com
    ```

2. Dockerイメージをビルドします（必要な場合）：

    ```sh
    docker build --platform=linux/amd64 -t rs-subscribe-auth .
    ```

3. イメージにECRリポジトリのタグを付けます：

    ```sh
    docker tag <your-project-name>:latest <your-account-id>.dkr.ecr.<your-region>.amazonaws.com/<your-repository-name>:latest
    ```

4. イメージをECRにプッシュします：

    ```sh
    docker push <your-account-id>.dkr.ecr.<your-region>.amazonaws.com/<your-repository-name>:latest
    ```

注意: 上記のコマンドで `<your-account-id>`、`<your-region>`、`<your-repository-name>` を適切な値に置き換えてください。

### セキュリティ注意事項

- AWSアカウントID、リージョン、リポジトリ名などの具体的な情報は公開リポジトリのREADMEに記載しないでください。
- AWSの認証情報を決してバージョン管理システムにコミットしないでください。

詳細については、[Amazon ECRドキュメント](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html)を参照してください。
