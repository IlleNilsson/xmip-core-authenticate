//! The broker's word for a message's sender, verified (ADR-0019, amendment
//! 2026-10-31).
//!
//! The `broker` identifier presents the sender a message broker delivered a
//! message as, with the transport's word under `broker.connection` where
//! the transport's own connection proved the broker. This is its
//! authenticator, which every node carries, as it carries the circumstance:
//! a Receive Location takes it only where its `accept.mechanism` names
//! `broker` and its `accept.transport` takes what it answers.
//!
//! **Vouched** where the transport says it proved the broker and names it:
//! the broker checked the sender against the connection it authenticated,
//! and Xmip proved the broker — as strong as that proof and never called
//! proven, because Xmip checked the broker and not the sender. **Claimed**
//! where the transport says nothing: a connection nothing proved could be
//! anyone's, and so could the field. **Refused** where the claim was not
//! read out of a delivery, names no sender, or the transport's word is
//! anything but `verified` or comes without the broker it is about.

use context::Verified;
use context::property::{BROKER, TLS_HANDSHAKE_VERIFIED as VERIFIED};
use identify::Presented;
use identify::evidence::BROKER_CONNECTION;
use xcore::{Established, Mechanism, mechanism};

use crate::{AuthenticateError, Authenticator};

/// The `broker` authenticator.
#[derive(Clone, Copy, Debug, Default)]
pub struct Broker;

impl Authenticator for Broker {
    fn mechanism(&self) -> Mechanism {
        mechanism::broker()
    }

    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError> {
        if presented.established != Established::Detected {
            return Err(AuthenticateError::new(format!(
                "a broker's sender is read out of the delivery it made, and this one was {}",
                presented.established
            )));
        }
        if presented.value.trim().is_empty() {
            return Err(AuthenticateError::new(
                "the broker's delivery names no sender",
            ));
        }
        let Some(word) = presented.proof(BROKER_CONNECTION) else {
            return Ok(Verified::Claimed);
        };
        if word.trim() != VERIFIED {
            return Err(AuthenticateError::new(format!(
                "the transport's word on its connection to the broker is '{}', not '{VERIFIED}'",
                word.trim()
            )));
        }
        match presented.evidence(BROKER).map(str::trim) {
            Some(broker) if !broker.is_empty() => Ok(Verified::Vouched),
            _ => Err(AuthenticateError::new(
                "the transport says it proved the broker and names no broker",
            )),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn delivered(sender: &str) -> Presented {
        Presented::detected(mechanism::broker(), sender)
    }

    #[test]
    fn a_proven_broker_vouches_and_an_unproven_one_is_only_claimed() {
        let proven = delivered("AIDAEXAMPLE")
            .with_evidence(BROKER, "sqs.eu-north-1.amazonaws.com")
            .with_proof(BROKER_CONNECTION, VERIFIED);
        assert_eq!(Broker.verify(&proven).ok(), Some(Verified::Vouched));

        let unproven = delivered("orders").with_evidence(BROKER, "broker.example");
        assert_eq!(Broker.verify(&unproven).ok(), Some(Verified::Claimed));
        assert_eq!(Broker.mechanism().name(), "broker");
    }

    #[test]
    fn another_word_a_word_naming_no_broker_a_passed_claim_and_no_sender_are_refused() {
        let other = delivered("orders")
            .with_evidence(BROKER, "broker.example")
            .with_proof(BROKER_CONNECTION, "trusted");
        assert!(Broker.verify(&other).is_err());

        let nameless = delivered("orders").with_proof(BROKER_CONNECTION, VERIFIED);
        assert!(Broker.verify(&nameless).is_err());

        let passed = Presented::passed(mechanism::broker(), "orders")
            .with_evidence(BROKER, "broker.example")
            .with_proof(BROKER_CONNECTION, VERIFIED);
        let refused = Broker.verify(&passed).expect_err("passed");
        assert!(refused.message.contains("passed"), "{}", refused.message);

        assert!(Broker.verify(&delivered(" ")).is_err());
    }
}
