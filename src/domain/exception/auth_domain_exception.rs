use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthDomainException {
    #[error("Validate Error")]
    ValidateFailed,

    #[error("Regex Compile Failed")]
    RegexCompilationFailed,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_auth_domain_exception_validate_failed() {
        assert_eq!(
            AuthDomainException::ValidateFailed.to_string(),
            "Validate Error"
        );
    }

    #[test]
    fn test_auth_domain_exception_regex_compilation_failed() {
        assert_eq!(
            AuthDomainException::RegexCompilationFailed.to_string(),
            "Regex Compile Failed"
        );
    }
}
