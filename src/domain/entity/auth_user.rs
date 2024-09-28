use crate::domain::exception::auth_domain_exception::AuthDomainException;
use regex::Regex;

/// Represents an authenticated user in the system.
#[derive(Debug, Clone)]
pub struct AuthUser {
    pub user_id: String,
    pub email: String,
    pub password: String,
    pub verify_code: String,
}

impl AuthUser {
    /// Creates a new AuthUser instance.
    ///
    /// # Arguments
    ///
    /// * `user_id` - A unique identifier for the user.
    /// * `email` - The user's email address.
    /// * `password` - The user's password.
    /// * `verify_code` - A code for user verification.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(AuthUser)` containing the new AuthUser instance if successful.
    /// - `Err(AuthDomainException)` if validation fails for email or password.
    pub fn new(
        user_id: &str,
        email: &str,
        password: &str,
        verify_code: &str,
    ) -> Result<Self, AuthDomainException> {
        Ok(AuthUser {
            user_id: user_id.into(),
            email: Self::set_email(email)?,
            password: Self::set_password(password)?,
            verify_code: verify_code.into(),
        })
    }

    /// Validates and sets the email address.
    ///
    /// # Arguments
    ///
    /// * `email` - The email address to validate and set.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(String)` containing the validated email if successful.
    /// - `Err(AuthDomainException)` if the email is invalid.
    fn set_email(email: &str) -> Result<String, AuthDomainException> {
        let regex = Regex::new(r"^[a-z0-9]([a-z0-9._%+-]{0,61}[a-z0-9])?@[a-z0-9-]{1,63}(\.[a-z0-9-]{1,63})*\.[a-z]{2,6}$")
            .map_err(|_| AuthDomainException::RegexCompilationFailed)?;
        if regex.is_match(email) {
            Ok(email.into())
        } else {
            Err(AuthDomainException::ValidateFailed)
        }
    }

    /// Validates and sets the password.
    ///
    /// # Arguments
    ///
    /// * `password` - The password to validate and set.
    ///
    /// # Returns
    ///
    /// Returns a `Result` which is either:
    /// - `Ok(String)` containing the validated password if successful.
    /// - `Err(AuthDomainException)` if the password is invalid.
    fn set_password(password: &str) -> Result<String, AuthDomainException> {
        if password.len() <= 6 {
            return Err(AuthDomainException::ValidateFailed);
        }

        let has_lowercase = password.chars().any(|c| c.is_ascii_lowercase());
        let has_uppercase = password.chars().any(|c| c.is_ascii_uppercase());

        if has_lowercase && has_uppercase {
            Ok(password.into())
        } else {
            Err(AuthDomainException::ValidateFailed)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use rstest::rstest;

    #[rstest]
    fn test_auth_user_create_success() {
        let result = AuthUser::new("123", "hoge@emial.com", "Hoge12345!!", "hogehoge").unwrap();

        assert_eq!(result.user_id, "123".to_string());
        assert_eq!(result.email, "hoge@emial.com".to_string());
        assert_eq!(result.password, "Hoge12345!!".to_string());
        assert_eq!(result.verify_code, "hogehoge".to_string());
    }

    #[rstest]
    #[test]
    #[case("simple@example.com")]
    #[case("very.common@example.com")]
    #[case("disposable.style.email.with+symbol@example.com")]
    #[case("other.email-with-hyphen@example.com")]
    #[case("fully-qualified-domain@example.com")]
    #[case("user.name+tag+sorting@example.com")]
    #[case("x@example.com")]
    #[case("example-indeed@strange-example.com")]
    #[case("user%example.com@example.org")]
    fn test_set_email_validate_success(#[case] email: String) {
        let result = AuthUser::set_email(&email);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), email)
    }

    #[rstest]
    #[case("")]
    #[case("plainaddress")]
    #[case("@missingusername.com")]
    #[case("user-@example.org")]
    #[case("username@.com")]
    #[case("username@domain.com.")]
    #[case(".username@domain.com")]
    #[case("username@domain..com")]
    #[case("username@domain@anotherdomain.com")]
    #[case("username@domain.c")]
    #[case("username@domain.toolong")]
    fn test_set_email_validate_failed(#[case] email: String) {
        let result = AuthUser::set_email(&email);

        assert!(result.is_err());
        assert!(matches!(result, Err(AuthDomainException::ValidateFailed)))
    }

    #[rstest]
    #[case("Password123")]
    #[case("StrongP@ssw0rd")]
    #[case("aA1!bB2@cC3#")]
    #[case("7CharAZ")]
    #[case("abcdefG")]
    #[case("ABCDEFg")]
    #[case("Mix3dPassw0rd")]
    #[case("LongPasswordWithUpperAndLowerCase")]
    #[case("ShortPW1")]
    #[case("UPPER123lower")]
    #[case("lower123UPPER")]
    #[case("PassWord@2023")]
    #[case("Aa1!Bb2@Cc3#Dd4$")]
    #[case("ThIs1sAV3ryL0ngAndC0mpl3xP@ssw0rd")]
    fn test_set_password_validate_success(#[case] password: String) {
        let result = AuthUser::set_password(&password);

        assert!(result.is_ok());
        assert_eq!(result.unwrap(), password)
    }

    #[rstest]
    #[case("")]
    #[case("a")]
    #[case("ab")]
    #[case("abc")]
    #[case("abcd")]
    #[case("abcde")]
    #[case("abcdef")]
    #[case("123456")]
    #[case("ABCDEF")]
    #[case("abcdefg")]
    #[case("ABCDEFG")]
    #[case("1234567")]
    #[case("!@#$%^&")]
    #[case("abcdefghijklmnop")]
    #[case("ABCDEFGHIJKLMNOP")]
    #[case("abcABC")]
    #[case("123ABC")]
    #[case("abc123")]
    #[case("ABC123")]
    fn test_set_password_validate_failed(#[case] password: String) {
        let result = AuthUser::set_password(&password);

        assert!(result.is_err());
        assert!(matches!(result, Err(AuthDomainException::ValidateFailed)))
    }
}
