//! A drop folder's implied identity, verified (ADR-0019 clause 7;
//! `terminology.md`, *Implied identity*).
//!
//! Where nothing identified anything — a file dropped in a folder, a raw
//! socket — the runtime infers the circumstance as the transport identity:
//! the place the Stream came from, `file:///C:/in/order.edi`, established
//! *inferred* (ADR-0019 clause 8). This is its authenticator: every node
//! infers a circumstance, so every node carries the verifier, and a Receive
//! Location takes it only where its `accept.mechanism` names
//! `circumstance` (clause 1, the closed set; ADR-0068: chosen by
//! configuration) and its `accept.transport` takes `claimed` (amendment
//! 2026-10-31). The owner, 2026-10-19: a drop folder's implied identity
//! is linked into the service and chosen by configuration, so a file
//! Receive Location can accept on a real node.
//!
//! What it verifies is what the circumstance is: a claim the node inferred
//! from where the Stream arrived, never one a sender presented. A
//! circumstance passed or detected is refused — nothing a sender writes
//! can be its own drop folder — and so is one naming no place. Nothing
//! cryptographic stands behind it, so the verdict is *claimed*; who may
//! write in the folder is the operating system's permissions, which the
//! operator sets, and a transport that reads them puts them beside the
//! claim as evidence (`file.owner`, `file.group`, `file.mode`).

use context::Verified;
use identify::Presented;
use xcore::{Established, Mechanism, mechanism};

use crate::{AuthenticateError, Authenticator};

/// The `circumstance` authenticator.
#[derive(Clone, Copy, Debug, Default)]
pub struct Circumstance;

impl Authenticator for Circumstance {
    fn mechanism(&self) -> Mechanism {
        mechanism::circumstance()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if presented.established != Established::Inferred {
            return Err(AuthenticateError::new(format!(
                "a circumstance is inferred by the node from where a Stream arrived, and this \
                 one was {}",
                presented.established
            )));
        }
        if presented.value.trim().is_empty() {
            return Err(AuthenticateError::new(
                "the circumstance names no place the Stream arrived from",
            ));
        }
        Ok(Verified::Claimed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn an_inferred_circumstance_is_claimed() {
        let folder = Presented::inferred(mechanism::circumstance(), "file:///in/order.edi");

        assert_eq!(Circumstance.verify(&folder).ok(), Some(Verified::Claimed));
        assert_eq!(Circumstance.mechanism().name(), "circumstance");
    }

    #[test]
    fn a_circumstance_a_sender_passed_or_naming_no_place_is_refused() {
        let passed = Presented::passed(mechanism::circumstance(), "file:///in/order.edi");
        let refused = Circumstance.verify(&passed).expect_err("passed");
        assert!(refused.message.contains("passed"), "{}", refused.message);

        let nowhere = Presented::inferred(mechanism::circumstance(), " ");
        assert!(Circumstance.verify(&nowhere).is_err());
    }
}
