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

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use mockall::Any;
    use super::*;

    struct TestClient
    where
        Self: Send + Sync,
    {
        flg: bool,
    }

    impl TestClient {
        fn new(flg: bool) -> Self {
            Self { flg }
        }
    }

    #[test]
    fn test_send() {
        fn is_send<T: Send>() {}
        is_send::<Arc<dyn AwsProvider<TestClient>>>();
        is_send::<TestClient>()
    }

    #[test]
    fn test_sync() {
        fn is_sync<T: Sync>() {}
        is_sync::<Arc<dyn AwsProvider<TestClient>>>();
        is_sync::<TestClient>()
    }

    #[async_trait]
    impl AwsProvider<TestClient> for TestClient {
        async fn get_aws_config(&self) -> Result<TestClient, AwsConfigError> {
            let client = TestClient::new(self.flg);
            if client.flg {
                Ok(TestClient::new(self.flg))
            } else {
                Err(AwsConfigError::EnvVarNotFound("hoge".to_string()))
            }
        }
    }

    #[tokio::test]
    async fn test_get_aws_config_success() {
        let client = TestClient::new(true);
        let result = TestClient::get_aws_config(&client).await;

        assert!(result.is_ok());
        assert_eq!(result.unwrap().type_name(), TestClient::new(true).type_name())
    }

    #[tokio::test]
    async fn test_get_aws_config_env_var_not_found() {
        let client = TestClient::new(false);
        let result = TestClient::get_aws_config(&client).await;

        assert!(result.is_err());
        assert!(matches!(
            result, Err(AwsConfigError::EnvVarNotFound(..))
        ))
    }

    #[test]
    fn test_env_var_not_found_message() {
        let err = AwsConfigError::EnvVarNotFound("hogehoge".to_string()).to_string();
        assert_eq!("Environment variable not found: hogehoge", err)
    }
}