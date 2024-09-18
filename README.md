# Rust Project Debug Setup

This README explains how to set up debugging for this Rust project using Visual Studio Code (VSCode).

## Prerequisites

- Visual Studio Code is installed
- Rust and Cargo are installed
- The "CodeLLDB" extension for VSCode is installed

## Debug Configuration

1. Create a `.vscode` folder in the project's root directory (if it doesn't exist).

2. Create a `launch.json` file inside the `.vscode` folder and paste the following content:

```json
{
  "version": "0.2.0",
  "configurations": [
    {
      "type": "lldb",
      "request": "launch",
      "name": "Debug executable",
      "cargo": {
        "args": [
          "build"
        ],
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

## Configuration Explanation

- `type`: Uses "lldb" for debugging, provided by the CodeLLDB extension.
- `request`: "launch" means starting a new process for debugging.
- `name`: The name of the debug configuration, displayed in VSCode's debug view.
- `cargo`: Configuration for the Cargo command.
    - `args`: Arguments passed to Cargo. Here, we use the `build` command.
    - `filter`: Limits the build to "bin" (executable files).
- `args`: Arguments passed to the program. Add as needed.
- `cwd`: The working directory for the program. `${workspaceFolder}` refers to the project's root directory.

## How to Start Debugging

1. Open the project in VSCode.
2. Open the Rust file you want to debug.
3. Set breakpoints as needed.
4. Press F5 or click the debug icon in the sidebar to start debugging.
5. Select the "Debug executable" configuration.

Now, the program will stop at breakpoints, allowing you to inspect variables, step through code, and perform other
debugging tasks.

## Notes

- This is a basic configuration. You may need to adjust `launch.json` based on your project's specific needs.
- If you need environment variables or additional arguments, add them to `launch.json` as necessary.
- For team development, each developer might need to adjust `launch.json` to fit their environment.

<br/>
<br/>
<br/>

# Deploying to ECR

Follow these steps to push the Docker image of this project to Amazon Elastic Container Registry (ECR).

### Prerequisites

- An AWS account with an ECR repository set up
- AWS CLI installed and properly configured
- Docker installed

### Steps

1. Log in to your AWS account:

    ```sh
    aws ecr get-login-password --region <your-region> | docker login --username AWS --password-stdin <your-account-id>.dkr.ecr.<your-region>.amazonaws.com
    ```

2. Build the Docker image (if necessary):

    ```sh
    docker build --platform=linux/amd64 -t rs-subscribe-auth .
    ```

3. Tag the image with your ECR repository:

    ```sh
    docker tag <your-project-name>:latest <your-account-id>.dkr.ecr.<your-region>.amazonaws.com/<your-repository-name>:latest
    ```

4. Push the image to ECR:

    ```sh
    docker push <your-account-id>.dkr.ecr.<your-region>.amazonaws.com/<your-repository-name>:latest
    ```

Note: Replace `<your-account-id>`, `<your-region>`, and `<your-repository-name>` with appropriate values in the above
commands.

### Security Considerations

- Do not include specific information such as AWS account IDs, regions, or repository names in README files of public
  repositories.
- Never commit AWS credentials to version control systems.

For more details, refer to
the [Amazon ECR documentation](https://docs.aws.amazon.com/AmazonECR/latest/userguide/what-is-ecr.html).

# Run Test, Check format and Clippy

You have to check this section before when you push to origin branch.

### Steps

1. Run Test

    ```sh
    cargo test --package rs-subscribe-auth --lib
    ```

2. Check Clippy

    ```sh
    cargo clippy
    ```

3. Check format

    ```sh
    cargo fmt -- --check
   
   //if you need
   cargo fmt
    ```