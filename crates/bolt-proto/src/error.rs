//! Bolt protocol error codes.

use thiserror::Error;

#[repr(u16)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ErrorCode {
    NoError             = 0x00,
    ProtocolViolation   = 0x01,
    InternalError       = 0x02,
    FlowControlError    = 0x03,
    StreamLimitError    = 0x04,
    StreamClosedError   = 0x05,
    FrameSizeError      = 0x06,
    AuthFailed          = 0x07,
    CryptoError         = 0x08,
    ConnectionRefused   = 0x09,
    VersionNegotiation  = 0x0A,
}

impl ErrorCode {
    pub fn is_fatal(&self) -> bool {
        !matches!(self, Self::NoError | Self::StreamLimitError | Self::StreamClosedError)
    }
}

impl std::fmt::Display for ErrorCode {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let s = match self {
            Self::NoError            => "NoError",
            Self::ProtocolViolation  => "ProtocolViolation",
            Self::InternalError      => "InternalError",
            Self::FlowControlError   => "FlowControlError",
            Self::StreamLimitError   => "StreamLimitError",
            Self::StreamClosedError  => "StreamClosedError",
            Self::FrameSizeError     => "FrameSizeError",
            Self::AuthFailed         => "AuthenticationFailed",
            Self::CryptoError        => "CryptoError",
            Self::ConnectionRefused  => "ConnectionRefused",
            Self::VersionNegotiation => "VersionNegotiation",
        };
        write!(f, "{}", s)
    }
}

#[derive(Debug, Error)]
#[error("bolt: {code}: {message}")]
pub struct BoltError {
    pub code:    ErrorCode,
    pub message: String,
}

impl BoltError {
    pub fn new(code: ErrorCode, message: impl Into<String>) -> Self {
        Self { code, message: message.into() }
    }
}
