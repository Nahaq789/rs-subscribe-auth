use anyhow::Context;
use aws_config::{meta::region::RegionProviderChain, BehaviorVersion};
use aws_sdk_cognitoidentityprovider::{config::Region, Client};
use axum::async_trait;
use dotenv::dotenv;
use std::env;

use hmac::{Hmac, Mac};
use sha2::Sha256;

use crate::adapter::aws::provider::{AwsConfigError, AwsProvider};
use base64::engine::general_purpose;
use base64::Engine as _;

/// Represents a client for interacting with AWS Cognito
///
/// This struct encapsulates the necessary information and client
/// to interact with AWS Cognito services.
#[derive(Debug, Clone)]
pub struct CognitoClient {
    /// The ID of the Cognito User Pool
    pub user_pool_id: String,
    /// The ID of the Cognito Client
    pub client_id: String,
    /// The AWS region
    pub region: String,
    /// The AWS COginito Secret Hash
    pub client_secret: String,
    /// The AWS Cognito Identity Provider client
    pub client: Client,
}

impl CognitoClient {
    /// Creates a new instance of CognitoClient
    ///
    /// # Arguments
    ///
    /// * `user_pool_id` - The ID of the Cognito User Pool
    /// * `client_id` - The ID of the Cognito Client
    /// * `region` - The AWS region
    /// * `client` - The AWS Cognito Identity Provider client
    ///
    /// # Returns
    ///
    /// A new instance of `CognitoClient`
    pub fn new(
        user_pool_id: String,
        client_id: String,
        region: String,
        secret_hash: String,
        client: Client,
    ) -> Self {
        CognitoClient {
            user_pool_id,
            client_id,
            region,
            client_secret: secret_hash,
            client,
        }
    }

    /// Creates a CognitoClient instance from environment variables
    ///
    /// This function reads necessary configuration from environment variables
    /// and initializes an AWS Cognito client.
    ///
    /// # Environment Variables
    ///
    /// * `AWS_USER_POOL_ID` - The ID of the Cognito User Pool
    /// * `AWS_CLIENT_ID` - The ID of the Cognito Client
    /// * `AWS_REGION` - The AWS region
    ///
    /// # Errors
    ///
    /// Returns an `AwsConfigError` if any required environment variable is missing
    /// or if there's an error initializing the AWS client.
    pub async fn from_env() -> Result<Self, AwsConfigError> {
        dotenv().ok();

        let user_pool_id = env::var("AWS_USER_POOL_ID")
            .context("AWS_USER_POOL_ID not found")
            .map_err(|e| AwsConfigError::EnvVarNotFound(e.to_string()))?;
        let client_id = env::var("AWS_CLIENT_ID")
            .context("AWS_CLIENT_ID not found")
            .map_err(|e| AwsConfigError::EnvVarNotFound(e.to_string()))?;
        let region = env::var("AWS_REGION")
            .context("AWS_REGION not found")
            .map_err(|e| AwsConfigError::EnvVarNotFound(e.to_string()))?;
        let client_secret = env::var("AWS_CLIENT_SECRET")
            .context("AWS_CLIENT_SECRET not found")
            .map_err(|e| AwsConfigError::EnvVarNotFound(e.to_string()))?;

        let region_provider = RegionProviderChain::first_try(Region::new(region.clone()));
        let shared_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;
        let client = Client::new(&shared_config);

        Ok(Self::new(
            user_pool_id,
            client_id,
            region,
            client_secret,
            client,
        ))
    }

    pub fn client_secret_hash(user_email: &str, client_id: &str, client_secret: &str) -> String {
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(client_secret.as_bytes())
            .expect("HMAC can take key of any size");

        mac.update(user_email.as_bytes());
        mac.update(client_id.as_bytes());
        let result = mac.finalize();
        general_purpose::STANDARD.encode(result.into_bytes())
    }
}

/// Implementation of AwsProvider trait for CognitoClient
#[async_trait]
impl AwsProvider<CognitoClient> for CognitoClient {
    /// Retrieves the AWS configuration for CognitoClient
    ///
    /// This implementation creates a new CognitoClient instance from environment variables
    /// each time it's called. This might not be the most efficient approach for frequent calls.
    ///
    /// # Returns
    ///
    /// A Result containing either a new CognitoClient instance or an AwsConfigError
    ///
    /// # Errors
    ///
    /// Returns an `AwsConfigError` if there's an issue creating the CognitoClient
    async fn get_aws_config(&self) -> Result<CognitoClient, AwsConfigError> {
        CognitoClient::from_env().await
    }
}

// ===== TEST SECTION START =====
// The following modules contains all unit tests for the CognitoClient.
// These tests verify the correct functionality of CognitoClient creation and initialization.
// Note: Some tests may require specific environment variables to be set.
#[cfg(test)]
mod cognito_client_tests {
    use super::*;

    #[tokio::test]
    async fn create_cognito_client_test() {
        // Test case: Creation of CognitoClient
        // This test verifies that a CognitoClient can be correctly instantiated
        // with provided parameters and that all its fields are properly set.

        // Set up test parameters
        let user_pool_id = "hoge_pool_id";
        let client_id = "hoge_client_id";
        let region = "hoge_region";
        let client_secret = "hoge_secret";

        // Create a region provider using the test region
        let region_provider = RegionProviderChain::first_try(Region::new(region));

        // Load AWS SDK configuration with the specified region
        let shared_config = aws_config::defaults(BehaviorVersion::latest())
            .region(region_provider)
            .load()
            .await;

        // Create an AWS Cognito Client using the shared configuration
        let client: Client = Client::new(&shared_config);

        // Instantiate the CognitoClient with test parameters and the AWS Cognito Client
        let cognito_client = CognitoClient::new(
            user_pool_id.into(),
            client_id.into(),
            region.into(),
            client_secret.into(),
            client,
        );

        // Wrap the client in an Option for null-safety check
        let option_client: Option<Client> = Some(cognito_client.client);

        // Assert that all fields of CognitoClient are set correctly
        assert_eq!(
            user_pool_id, cognito_client.user_pool_id,
            "user_pool_id mismatch"
        );
        assert_eq!(client_id, cognito_client.client_id, "client_id mismatch");
        assert_eq!(region, cognito_client.region, "region mismatch");
        assert_eq!(
            client_secret, cognito_client.client_secret,
            "client_secret mismatch"
        );

        // Verify that the client field is not null (Some)
        assert!(option_client.is_some(), "Client should not be null");
    }

    #[tokio::test]
    async fn from_env_test() {
        // Test case: Creation of CognitoClient from environment variables
        // This test ensures that CognitoClient can be successfully created
        // using the from_env() method, which loads configuration from environment variables.

        // Attempt to create a CognitoClient using from_env() method
        // The result is immediately wrapped in Some to convert it to an Option
        let result: Option<CognitoClient> = Some(CognitoClient::from_env().await.unwrap());

        // Assert that the result is Some, indicating successful creation
        assert!(
            result.is_some(),
            "CognitoClient should be successfully created from environment variables"
        );

        // Note: For this test to pass, the necessary environment variables must be set correctly.
        // It's recommended to document the required environment variables and their expected values
        // to ensure reproducibility of this test across different environments.
    }
}
