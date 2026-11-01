//! A local endpoint's caller, verified: the account the operating system
//! names for the process at the other end (ADR-0009, amendment 2026-10-21;
//! `terminology.md`, *Local endpoint*).
//!
//! On a node's local endpoint — a named pipe on Windows, a Unix domain
//! socket elsewhere — nothing is presented: the node reads the account the
//! connecting process runs as from the connection, the identity a pipe's
//! client lends for identification alone, or the kernel's word on a
//! socket's peer (`SO_PEERCRED`, `getpeereid`). The node writes the claim
//! *detected*, read out of the connection, with the proof
//! `peer-credentials.system` saying `verified` where the operating system
//! named the peer. This is its authenticator, which every node carries, as
//! it carries the circumstance: every node's operate listener has a local
//! endpoint (ADR-0050, amendment 2026-10-20).
//!
//! **Proven** where the operating system named an account: the kernel
//! stands behind it, and no caller can write it. **Refused** where the
//! claim was passed or inferred — nothing a caller says is its own peer's
//! account — where it names no account, or where the node's word is
//! missing or anything but `verified`.

use context::Verified;
use context::property::TLS_HANDSHAKE_VERIFIED as VERIFIED;
use identify::Presented;
use identify::evidence::PEER_CREDENTIALS_SYSTEM;
use xcore::{Established, Mechanism, mechanism};

use crate::{AuthenticateError, Authenticator};

/// The `peer-credentials` authenticator.
#[derive(Clone, Copy, Debug, Default)]
pub struct PeerCredentials;

impl Authenticator for PeerCredentials {
    fn mechanism(&self) -> Mechanism {
        mechanism::peer_credentials()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if presented.established != Established::Detected {
            return Err(AuthenticateError::new(format!(
                "a peer's account is read from the connection by the operating system, and \
                 this one was {}",
                presented.established
            )));
        }
        if presented.value.trim().is_empty() {
            return Err(AuthenticateError::new(
                "the operating system named no account for the peer",
            ));
        }
        match presented.proof(PEER_CREDENTIALS_SYSTEM).map(str::trim) {
            Some(VERIFIED) => Ok(Verified::Proven),
            Some(word) => Err(AuthenticateError::new(format!(
                "the node's word on the peer's account is '{word}', not '{VERIFIED}'"
            ))),
            None => Err(AuthenticateError::new(format!(
                "no {PEER_CREDENTIALS_SYSTEM} proof was presented: the operating system did not \
                 name the peer"
            ))),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read(account: &str) -> Presented {
        Presented::detected(mechanism::peer_credentials(), account)
            .with_proof(PEER_CREDENTIALS_SYSTEM, VERIFIED)
    }

    #[test]
    fn an_account_the_operating_system_named_is_proven() {
        let verified = PeerCredentials.verify(&read(r"CORP\jane"));
        assert_eq!(verified.ok(), Some(Verified::Proven));
        assert_eq!(PeerCredentials.mechanism().name(), "peer-credentials");
    }

    #[test]
    fn a_passed_account_no_account_and_no_or_another_word_are_refused() {
        let passed = Presented::passed(mechanism::peer_credentials(), "jane")
            .with_proof(PEER_CREDENTIALS_SYSTEM, VERIFIED);
        let refused = PeerCredentials.verify(&passed).expect_err("passed");
        assert!(refused.message.contains("passed"), "{}", refused.message);

        assert!(PeerCredentials.verify(&read(" ")).is_err());

        let unsaid = Presented::detected(mechanism::peer_credentials(), "jane");
        let refused = PeerCredentials.verify(&unsaid).expect_err("no word");
        assert!(refused.message.contains("did not"), "{}", refused.message);

        let other = Presented::detected(mechanism::peer_credentials(), "jane")
            .with_proof(PEER_CREDENTIALS_SYSTEM, "trusted");
        assert!(PeerCredentials.verify(&other).is_err());
    }
}
