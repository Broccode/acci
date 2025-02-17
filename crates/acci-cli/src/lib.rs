use serde::Serialize;
use std::fmt::Display;

#[must_use] pub const fn add(left: u64, right: u64) -> u64 {
    left + right
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        let result = add(2, 2);
        assert_eq!(result, 4);
    }
}

#[derive(Debug, Serialize)]
pub struct CliError {
    pub code: ErrorCode,
    pub message: String,
    pub details: Option<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ErrorCode {
    ValidationError,
    DatabaseError,
    InputError,
    SystemError,
}

impl CliError {
    pub fn validation(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::ValidationError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    pub fn database(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::DatabaseError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    pub fn input(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::InputError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    pub fn system(message: impl Into<String>, details: Option<impl Into<String>>) -> Self {
        Self {
            code: ErrorCode::SystemError,
            message: message.into(),
            details: details.map(Into::into),
        }
    }

    pub fn print(&self) {
        match serde_json::to_string_pretty(self) {
            Ok(json) => eprintln!("{json}"),
            Err(_) => eprintln!("Error: {} ({})", self.message, self.code),
        }
    }
}

impl Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ValidationError => write!(f, "validation_error"),
            Self::DatabaseError => write!(f, "database_error"),
            Self::InputError => write!(f, "input_error"),
            Self::SystemError => write!(f, "system_error"),
        }
    }
}
