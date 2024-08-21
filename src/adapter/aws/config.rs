use std::env;

use anyhow::Ok;

#[derive(Debug, Clone)]
pub struct AwsConfig {
    user_pool_id: String,
    client_id: String,
}

impl AwsConfig {
    fn from_lambda_env() -> Result<Self, env::VarError> {
        let config = AwsConfig {
            user_pool_id: env::var("AWS_USER_POOL_ID")?,
            client_id: env::var("AWS_CLIENT_ID")?,
        };

        Ok(config.)
    }
}
