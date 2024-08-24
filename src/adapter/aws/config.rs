use dotenv::dotenv;
use std::env;
use thiserror::Error;

#[derive(Debug, Clone)]
pub struct AwsConfig {
    pub user_pool_id: String,
    pub client_id: String,
}

#[derive(Error, Debug)]
pub enum AwsConfigError {
    #[error("Environment variable not found: {0}")]
    EnvVarNotFound(String),
}

impl AwsConfig {
    fn new(user_pool_id: String, client_id: String) -> Self {
        AwsConfig {
            user_pool_id,
            client_id,
        }
    }

    pub fn get_env_value() -> Result<Self, AwsConfigError> {
        dotenv().ok();
        let user_pool_id = env::var("AWS_USER_POOL_ID")
            .map_err(|_| AwsConfigError::EnvVarNotFound("AWS_USER_POOL_ID".to_string()))?;
        let client_id = env::var("AWS_CLIENT_ID")
            .map_err(|_| AwsConfigError::EnvVarNotFound("AWS_CLIENT_ID".to_string()))?;

        let config = AwsConfig::new(user_pool_id, client_id);

        Ok(config)
    }
}
