use regex::Regex;
use serde::{Deserialize, Serialize};
use crate::domain::exception::auth_domain_exception::AuthDomainException;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
    pub password: String,
    pub verify_code: String,
}

impl AuthUser {
    pub fn new(user_id: String, email: String, password: String, verify_code: String) -> Result<Self, AuthDomainException> {
        Ok(AuthUser {
            user_id,
            email: Self::set_email(email)?,
            password: Self::set_password(password)?,
            verify_code,
        })
    }

    fn set_email(email: String) -> Result<String, AuthDomainException> {
        let regex = Regex::new(r"^[a-z0-9._%+-]+@[a-z0-9.-]+\.[a-z]{2,4}$")
            .map_err(|_| AuthDomainException::RegexCompilationFailed)?;
        if regex.is_match(&email) {
            Ok(email)
        } else {
            Err(AuthDomainException::ValidateFailed)
        }
    }

    fn set_password(password: String) -> Result<String, AuthDomainException> {
        let regex = Regex::new(r"").map_err(|_| AuthDomainException::RegexCompilationFailed)?;
        if regex.is_match(&password) {
            Ok(password)
        } else {
            Err(AuthDomainException::ValidateFailed)
        }
    }
}