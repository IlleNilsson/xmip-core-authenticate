//! A mutual-tls handshake, verified: the one rule for what a transport
//! that terminated it says (ADR-0033; ADR-0019, amendment 2026-10-30).
//!
//! A `mutual-tls` handshake is proven at the transport: the TLS server
//! requested the client certificate, verified its chain to the anchors it
//! was configured with, and only then read a byte. The first gate presents
//! the subject with the `mutual-tls.handshake` proof the transport wrote —
//! `verified`, and nothing else counts — and this answers Proven for it and
//! refuses it where the proof is missing or says anything else.
//!
//! Every node's operate listener verifies a handshake for every caller it
//! serves, as every node infers a circumstance, so the rule stands beside
//! the capability's trait (ADR-0050, amendment 2026-10-20) and the
//! `mutual-tls` technology asks it before it narrows by issuer. The runtime
//! asks it of an operator's certificate (`plane::caller`), which no
//! technology a site links may decide.

use context::Verified;
use context::property::TLS_HANDSHAKE_VERIFIED as VERIFIED;
use identify::Presented;
use identify::evidence::MUTUAL_TLS_HANDSHAKE;
use xcore::{Mechanism, mechanism};

use crate::{AuthenticateError, Authenticator};

/// The handshake's authenticator: proven where the transport says its
/// handshake verified the client's certificate.
#[derive(Clone, Copy, Debug, Default)]
pub struct Handshake;

impl Authenticator for Handshake {
    fn mechanism(&self) -> Mechanism {
        mechanism::mutual_tls()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        let handshake = presented.proof(MUTUAL_TLS_HANDSHAKE).ok_or_else(|| {
            AuthenticateError::new(format!(
                "no {MUTUAL_TLS_HANDSHAKE} proof was presented: \
                 the transport did not say it verified the peer"
            ))
        })?;
        if handshake.trim() != VERIFIED {
            return Err(AuthenticateError::new(format!(
                "the transport's word on the handshake is '{}', not '{VERIFIED}'",
                handshake.trim()
            )));
        }
        if presented.value.trim().is_empty() {
            return Err(AuthenticateError::new(
                "the handshake's certificate names no subject",
            ));
        }
        Ok(Verified::Proven)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn presented(handshake: Option<&str>) -> Presented {
        let claim = Presented::passed(mechanism::mutual_tls(), "CN=party-x.example");
        match handshake {
            Some(word) => claim.with_proof(MUTUAL_TLS_HANDSHAKE, word),
            None => claim,
        }
    }

    #[test]
    fn what_the_handshake_verified_is_proven() {
        let verified = Handshake.verify(&presented(Some("verified")));
        assert_eq!(verified.ok(), Some(Verified::Proven));
        assert_eq!(Handshake.mechanism().name(), "mutual-tls");
    }

    #[test]
    fn a_claim_the_transport_did_not_vouch_for_or_naming_no_one_is_refused() {
        let failure = Handshake.verify(&presented(None)).expect_err("no proof");
        assert!(failure.message.contains("did not say"), "{failure}");

        let failure = Handshake
            .verify(&presented(Some("requested")))
            .expect_err("not verified");
        assert!(failure.message.contains("'requested'"), "{failure}");

        let nameless = Presented::passed(mechanism::mutual_tls(), " ")
            .with_proof(MUTUAL_TLS_HANDSHAKE, VERIFIED);
        assert!(Handshake.verify(&nameless).is_err());
    }
}
