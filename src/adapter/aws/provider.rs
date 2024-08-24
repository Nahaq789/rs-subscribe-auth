use aws_sdk_cognitoidentityprovider::Client;
use axum::async_trait;
use thiserror::Error;

#[async_trait]
pub trait AwsProvider<T>: Send + Sync {
    async fn get_aws_config(&self) -> Result<T, AwsConfigError>;
}

#[derive(Error, Debug)]
pub enum AwsConfigError {
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
}
