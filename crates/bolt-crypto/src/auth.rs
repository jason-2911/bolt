//! Server-side client authentication.

use thiserror::Error;

use crate::keys::AuthorizedKeys;

pub struct Authenticator {
    authorized: AuthorizedKeys,
}

impl Authenticator {
    pub fn new(authorized: AuthorizedKeys) -> Self {
        Self { authorized }
    }

    /// Returns `Ok(())` if `client_pub_key` is in the authorized keys list.
    pub fn authenticate(&self, client_pub_key: &[u8; 32]) -> Result<(), AuthError> {
        if self.authorized.is_authorized(client_pub_key) {
            Ok(())
        } else {
            Err(AuthError::NotAuthorized)
        }
    }
}

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("public key not authorized")]
    NotAuthorized,
}
