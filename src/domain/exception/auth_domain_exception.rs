use thiserror::Error;

#[derive(Error, Debug)]
pub enum AuthDomainException {
    #[error("Validate Error")]
    ValidateFailed,

    #[error("Regex Compile Failed")]
    RegexCompilationFailed,
}
