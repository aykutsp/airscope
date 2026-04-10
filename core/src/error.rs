use thiserror::Error;

pub type Result<T, E = Error> = std::result::Result<T, E>;

#[derive(Debug, Error)]
pub enum Error {
    #[error("parse error: {0}")]
    Parse(String),

    #[error("unsupported: {0}")]
    Unsupported(String),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),

    #[error("capture: {0}")]
    Capture(String),

    #[error("injection: {0}")]
    Injection(String),

    #[error("invalid channel: {0}")]
    InvalidChannel(u16),

    #[error("{0}")]
    Msg(String),
}

impl From<&str> for Error {
    fn from(s: &str) -> Self {
        Error::Msg(s.to_string())
    }
}

impl From<String> for Error {
    fn from(s: String) -> Self {
        Error::Msg(s)
    }
}
