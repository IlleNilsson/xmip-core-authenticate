#![forbid(unsafe_code)]

use std::error::Error;
use std::fmt;
use xmip_party::Party;

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct CredentialReference {
    pub kind: String,
    pub reference: String,
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub struct AuthenticationResult {
    pub authenticated: bool,
    pub method: String,
    pub claims: Vec<(String, String)>,
}

#[derive(Debug)]
pub struct AuthenticateError {
    pub message: String,
}

impl fmt::Display for AuthenticateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result { f.write_str(&self.message) }
}
impl Error for AuthenticateError {}

pub trait Authenticator: Send + Sync {
    fn authenticate(
        &self,
        party: &Party,
        credential: &CredentialReference,
    ) -> Result<AuthenticationResult, AuthenticateError>;
}
