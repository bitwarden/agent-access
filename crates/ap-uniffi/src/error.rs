use ap_client::ClientError;

/// FFI-friendly error enum that maps the internal ClientError
/// into 6 categories suitable for cross-language consumption.
#[derive(Debug, thiserror::Error, uniffi::Error)]
pub enum RemoteAccessError {
    #[error("Connection failed: {message}")]
    ConnectionFailed { message: String },
    #[error("Handshake failed: {message}")]
    HandshakeFailed { message: String },
    #[error("Credential request failed: {message}")]
    CredentialRequestFailed { message: String },
    #[error("Session error: {message}")]
    SessionError { message: String },
    #[error("Invalid argument: {message}")]
    InvalidArgument { message: String },
    #[error("Timeout: {message}")]
    Timeout { message: String },
}

impl From<ClientError> for RemoteAccessError {
    fn from(err: ClientError) -> Self {
        let message = err.to_string();
        match err {
            ClientError::ConnectionFailed(_) | ClientError::WebSocket(_) => {
                RemoteAccessError::ConnectionFailed { message }
            }

            ClientError::ProxyAuthFailed(_)
            | ClientError::HandshakeFailed(_)
            | ClientError::NoiseProtocol(_)
            | ClientError::FingerprintRejected => RemoteAccessError::HandshakeFailed { message },

            ClientError::CredentialRequestFailed(_)
            | ClientError::SecureChannelNotEstablished
            | ClientError::NotInitialized => RemoteAccessError::CredentialRequestFailed { message },

            ClientError::ConnectionCache(_)
            | ClientError::IdentityStorageFailed(_)
            | ClientError::KeypairStorage(_)
            | ClientError::ConnectionNotFound
            | ClientError::Serialization(_)
            | ClientError::ChannelClosed => RemoteAccessError::SessionError { message },

            ClientError::InvalidPairingCode(_)
            | ClientError::InvalidRendezvousCode(_)
            | ClientError::RendezvousResolutionFailed(_)
            | ClientError::InvalidState { .. } => RemoteAccessError::InvalidArgument { message },

            ClientError::Timeout(_) => RemoteAccessError::Timeout { message },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn connection_failed_maps_correctly() {
        let err = ClientError::ConnectionFailed("refused".to_string());
        let mapped = RemoteAccessError::from(err);
        assert!(matches!(mapped, RemoteAccessError::ConnectionFailed { .. }));
        assert!(mapped.to_string().contains("refused"));
    }

    #[test]
    fn websocket_error_maps_to_connection_failed() {
        let err = ClientError::WebSocket("closed".to_string());
        let mapped = RemoteAccessError::from(err);
        assert!(matches!(mapped, RemoteAccessError::ConnectionFailed { .. }));
    }

    #[test]
    fn handshake_errors_map_correctly() {
        let cases = vec![
            ClientError::ProxyAuthFailed("bad auth".to_string()),
            ClientError::HandshakeFailed("noise error".to_string()),
            ClientError::NoiseProtocol("decrypt failed".to_string()),
            ClientError::FingerprintRejected,
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::HandshakeFailed { .. }),
                "Expected HandshakeFailed, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn credential_errors_map_correctly() {
        let cases = vec![
            ClientError::CredentialRequestFailed("denied".to_string()),
            ClientError::SecureChannelNotEstablished,
            ClientError::NotInitialized,
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::CredentialRequestFailed { .. }),
                "Expected CredentialRequestFailed, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn session_errors_map_correctly() {
        let cases = vec![
            ClientError::ConnectionCache("corrupt".to_string()),
            ClientError::IdentityStorageFailed("missing".to_string()),
            ClientError::KeypairStorage("bad key".to_string()),
            ClientError::ConnectionNotFound,
            ClientError::Serialization("invalid json".to_string()),
            ClientError::ChannelClosed,
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::SessionError { .. }),
                "Expected SessionError, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn invalid_argument_errors_map_correctly() {
        let cases = vec![
            ClientError::InvalidPairingCode("bad code".to_string()),
            ClientError::InvalidRendezvousCode("too short".to_string()),
            ClientError::RendezvousResolutionFailed("not found".to_string()),
            ClientError::InvalidState {
                expected: "Ready".to_string(),
                current: "Init".to_string(),
            },
        ];
        for err in cases {
            let mapped = RemoteAccessError::from(err);
            assert!(
                matches!(mapped, RemoteAccessError::InvalidArgument { .. }),
                "Expected InvalidArgument, got: {mapped:?}"
            );
        }
    }

    #[test]
    fn timeout_maps_correctly() {
        let err = ClientError::Timeout("5s elapsed".to_string());
        let mapped = RemoteAccessError::from(err);
        assert!(matches!(mapped, RemoteAccessError::Timeout { .. }));
        assert!(mapped.to_string().contains("5s elapsed"));
    }

    #[test]
    fn invalid_state_preserves_fields_in_message() {
        let err = ClientError::InvalidState {
            expected: "Connected".to_string(),
            current: "Disconnected".to_string(),
        };
        let mapped = RemoteAccessError::from(err);
        let msg = mapped.to_string();
        assert!(msg.contains("Connected"));
        assert!(msg.contains("Disconnected"));
    }
}
