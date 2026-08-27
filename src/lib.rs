#![forbid(unsafe_code)]

//! Verifying a presented credential, and resolving it to a Party.
//!
//! ADR-0019 clause 2 orders the gates and the order does not vary by transport:
//!
//! ```text
//! identity  ->  authentication  ->  authorization
//! who is claimed    is the claim true    may this true identity do this
//! ```
//!
//! This module is the middle box. It is handed what arrived and what the
//! Receive Location declared it would take, and it answers with an
//! [`AuthenticatedIdentity`] or a [`Refusal`].
//!
//! **The Party is the output, never the input.** An earlier signature here took
//! a `&Party` and a credential, which required knowing who the caller was
//! before checking who the caller was. Authentication verifies the presented
//! credential and *resolves it to* a Party, per ADR-0019 clause 4.

use std::error::Error;
use std::fmt;
use xmip_context::{AuthenticatedIdentity, Verified};
use xmip_core::PartyId;
use xmip_party::{Mechanism, Party, Purpose};

/// What arrived, before anything has been checked.
///
/// The secret does not appear here. Whatever proves the claim — a signature, a
/// ticket, a password hash comparison — is the [`Authenticator`]'s business and
/// belongs to the protocol it implements.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Presented {
    pub mechanism: Mechanism,
    /// The claimed value — `CN=partner-x.example`, `sub=partner-x`.
    pub value: String,
    /// What the transport observed. Goes onto the record either way.
    pub evidence: Vec<(String, String)>,
}

impl Presented {
    #[must_use]
    pub fn new(mechanism: Mechanism, value: impl Into<String>) -> Self {
        Self {
            mechanism,
            value: value.into(),
            evidence: Vec::new(),
        }
    }

    #[must_use]
    pub fn with_evidence(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.evidence.push((name.into(), value.into()));
        self
    }
}

/// What a Receive Location declares it will take. ADR-0019 clause 1.
///
/// A **closed set**. An identity presented by a mechanism not declared here is
/// refused, and is not then attempted against the other configured mechanisms.
///
/// Trying every configured mechanism against every caller is how credential
/// stuffing across mechanisms works, and how a downgrade to the weakest
/// configured scheme works. It is also slow, in the one place in Xmip where
/// latency is paid by a caller waiting on a connection.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Acceptance {
    mechanisms: Vec<String>,
    parties: Vec<PartyId>,
}

impl Acceptance {
    /// Accepts nothing.
    ///
    /// The deliberate failure mode from ADR-0019: a Receive Location that
    /// declares no accepted mechanism accepts nothing. An unconfigured endpoint
    /// is closed, not open.
    #[must_use]
    pub fn closed() -> Self {
        Self::default()
    }

    #[must_use]
    pub fn accepting(mut self, mechanism: &Mechanism) -> Self {
        self.mechanisms.push(mechanism.name().to_string());
        self
    }

    /// Narrow to named Parties. Left empty, any Party the registry resolves is
    /// accepted.
    #[must_use]
    pub fn from_party(mut self, party_id: PartyId) -> Self {
        self.parties.push(party_id);
        self
    }

    #[must_use]
    pub fn declares(&self, mechanism: &Mechanism) -> bool {
        self.mechanisms.iter().any(|name| name == mechanism.name())
    }

    #[must_use]
    pub fn permits(&self, party_id: PartyId) -> bool {
        self.parties.is_empty() || self.parties.contains(&party_id)
    }

    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.mechanisms.is_empty()
    }
}

/// Why an arrival did not authenticate.
///
/// Each variant names something an operator can act on. "Authentication
/// failed" without the reason is a message that sends someone reading
/// configuration files for an afternoon.
#[derive(Clone, Debug, Eq, PartialEq)]
pub enum Refusal {
    /// The Receive Location declares no mechanism at all.
    LocationAcceptsNothing,
    /// Presented by a mechanism this location does not declare. Not attempted
    /// against the others — that is the rule, not an optimisation.
    MechanismNotDeclared { presented: String },
    /// Declared, and nothing loaded can verify it.
    NoAuthenticator { mechanism: String },
    /// The mechanism ran and the claim did not hold.
    NotProven { mechanism: String, detail: String },
    /// Verified, and resolved to a Party this location does not take.
    PartyNotPermitted { party_id: PartyId },
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LocationAcceptsNothing => {
                f.write_str("the Receive Location declares no accepted mechanism")
            }
            Self::MechanismNotDeclared { presented } => write!(
                f,
                "'{presented}' was presented and this Receive Location does not declare it"
            ),
            Self::NoAuthenticator { mechanism } => {
                write!(f, "'{mechanism}' is declared and no module implements it")
            }
            Self::NotProven { mechanism, detail } => write!(f, "'{mechanism}' refused: {detail}"),
            Self::PartyNotPermitted { party_id } => {
                write!(f, "resolved to {party_id}, which this location does not take")
            }
        }
    }
}

impl Error for Refusal {}

#[derive(Debug)]
pub struct AuthenticateError {
    pub message: String,
}

impl fmt::Display for AuthenticateError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}

impl Error for AuthenticateError {}

/// One mechanism, implemented by one module.
///
/// `xmip-core-authenticate-mutual-tls`, `-kerberos`, `-oauth2` and the rest.
pub trait Authenticator: Send + Sync {
    fn mechanism(&self) -> Mechanism;

    /// Verify the claim. Returns what was concluded, not whether it passed —
    /// [`Verified::Claimed`] is a legitimate answer for a mechanism carrying no
    /// cryptography.
    fn verify(&self, presented: &Presented) -> Result<Verified, AuthenticateError>;
}

/// Where a verified value is looked up.
///
/// A registry lookup, not a decision. Resolving to nothing is ordinary and
/// decides nothing by itself: a Party is a shortcut to an identity, not a
/// permission.
pub trait PartyRegistry: Send + Sync {
    /// Find the Party a presented value belongs to.
    fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<Party>;

    /// Find a Party already named.
    ///
    /// The send side needs this: ADR-0006 resolves *which* Party's identity to
    /// present through the Send Location chain, and then the registry has to
    /// produce it. Looking up by value would be answering a question nobody
    /// asked.
    fn party(&self, party_id: PartyId) -> Option<Party>;
}

/// Run the authentication gate.
///
/// The order matters and is the clause-1 rule made executable: the declared set
/// is consulted *before* any authenticator runs, so an undeclared mechanism
/// never reaches verification and cannot be used to probe which mechanisms
/// exist.
///
/// # Errors
///
/// Returns the [`Refusal`] that stopped it, naming what an operator would need
/// to change.
pub fn authenticate(
    acceptance: &Acceptance,
    authenticators: &[&dyn Authenticator],
    registry: &dyn PartyRegistry,
    presented: &Presented,
) -> Result<AuthenticatedIdentity, Refusal> {
    if acceptance.is_closed() {
        return Err(Refusal::LocationAcceptsNothing);
    }

    if !acceptance.declares(&presented.mechanism) {
        return Err(Refusal::MechanismNotDeclared {
            presented: presented.mechanism.name().to_string(),
        });
    }

    let authenticator = authenticators
        .iter()
        .find(|candidate| candidate.mechanism().name() == presented.mechanism.name())
        .ok_or_else(|| Refusal::NoAuthenticator {
            mechanism: presented.mechanism.name().to_string(),
        })?;

    let verified = authenticator
        .verify(presented)
        .map_err(|failure| Refusal::NotProven {
            mechanism: presented.mechanism.name().to_string(),
            detail: failure.message,
        })?;

    if verified == Verified::Refused {
        return Err(Refusal::NotProven {
            mechanism: presented.mechanism.name().to_string(),
            detail: "the claim did not hold".to_string(),
        });
    }

    let mut identity =
        AuthenticatedIdentity::new(presented.mechanism.clone(), &presented.value, verified);

    for (name, value) in &presented.evidence {
        identity = identity.with_evidence(name, value);
    }

    // The lookup happens after verification, never before. Resolving first
    // would leak which values are known to an unauthenticated caller.
    if let Some(party) = registry.resolve(
        presented.mechanism.name(),
        Purpose::Receive,
        &presented.value,
    ) {
        if !acceptance.permits(party.party_id) {
            return Err(Refusal::PartyNotPermitted {
                party_id: party.party_id,
            });
        }

        identity = identity.resolving_to(party.party_id);
    }

    Ok(identity)
}

#[cfg(test)]
mod tests {
    use super::*;
    use xmip_party::{mechanism, Identity, PartyKind};

    struct Always(Mechanism, Verified);

    impl Authenticator for Always {
        fn mechanism(&self) -> Mechanism {
            self.0.clone()
        }

        fn verify(&self, _presented: &Presented) -> Result<Verified, AuthenticateError> {
            Ok(self.1)
        }
    }

    struct Registry(Vec<Party>);

    impl PartyRegistry for Registry {
        fn resolve(&self, mechanism: &str, purpose: Purpose, value: &str) -> Option<Party> {
            self.0
                .iter()
                .find(|party| party.identity(mechanism, purpose) == Some(value))
                .cloned()
        }

        fn party(&self, party_id: PartyId) -> Option<Party> {
            self.0.iter().find(|party| party.party_id == party_id).cloned()
        }
    }

    fn registry() -> Registry {
        Registry(vec![Party::new(
            PartyId::new(1),
            PartyKind::Organization,
            "partner-x",
        )
        .with(Identity::receiving(
            mechanism::mutual_tls(),
            "CN=partner-x.example",
        ))])
    }

    fn tls_proves() -> Always {
        Always(mechanism::mutual_tls(), Verified::Proven)
    }

    #[test]
    fn a_verified_credential_resolves_to_a_party() {
        let identity = authenticate(
            &Acceptance::closed().accepting(&mechanism::mutual_tls()),
            &[&tls_proves()],
            &registry(),
            &Presented::new(mechanism::mutual_tls(), "CN=partner-x.example"),
        )
        .expect("accepted");

        assert_eq!(identity.party_id, Some(PartyId::new(1)));
        assert_eq!(identity.verified, Verified::Proven);
    }

    #[test]
    fn an_undeclared_mechanism_is_never_attempted_against_the_declared_ones() {
        // The clause-1 rule. An api-key arrival at a mutual-tls location is
        // refused outright — not tried against mutual-tls, and not tried at
        // all. This is what stops a downgrade to the weakest configured scheme.
        let refusal = authenticate(
            &Acceptance::closed().accepting(&mechanism::mutual_tls()),
            &[&tls_proves(), &Always(mechanism::api_key(), Verified::Proven)],
            &registry(),
            &Presented::new(mechanism::api_key(), "k-123"),
        )
        .expect_err("refused");

        assert_eq!(
            refusal,
            Refusal::MechanismNotDeclared {
                presented: "api-key".to_string()
            }
        );
    }

    #[test]
    fn an_unconfigured_location_is_closed_rather_than_open() {
        let refusal = authenticate(
            &Acceptance::closed(),
            &[&tls_proves()],
            &registry(),
            &Presented::new(mechanism::mutual_tls(), "CN=partner-x.example"),
        )
        .expect_err("refused");

        assert_eq!(refusal, Refusal::LocationAcceptsNothing);
    }

    #[test]
    fn an_unresolved_caller_still_authenticates() {
        // A Party is a shortcut, not a permission. A verified credential the
        // registry has never seen is authenticated; whether it may do anything
        // is authorization's question.
        let identity = authenticate(
            &Acceptance::closed().accepting(&mechanism::mutual_tls()),
            &[&tls_proves()],
            &registry(),
            &Presented::new(mechanism::mutual_tls(), "CN=stranger.example"),
        )
        .expect("accepted");

        assert_eq!(identity.verified, Verified::Proven);
        assert_eq!(identity.party_id, None);
    }

    #[test]
    fn a_party_outside_the_declared_set_is_refused_after_verification() {
        let refusal = authenticate(
            &Acceptance::closed()
                .accepting(&mechanism::mutual_tls())
                .from_party(PartyId::new(99)),
            &[&tls_proves()],
            &registry(),
            &Presented::new(mechanism::mutual_tls(), "CN=partner-x.example"),
        )
        .expect_err("refused");

        assert_eq!(
            refusal,
            Refusal::PartyNotPermitted {
                party_id: PartyId::new(1)
            }
        );
    }

    #[test]
    fn a_declared_mechanism_with_no_module_says_so() {
        let refusal = authenticate(
            &Acceptance::closed().accepting(&mechanism::kerberos()),
            &[&tls_proves()],
            &registry(),
            &Presented::new(mechanism::kerberos(), "svc@CORP.EXAMPLE"),
        )
        .expect_err("refused");

        assert_eq!(
            refusal,
            Refusal::NoAuthenticator {
                mechanism: "kerberos".to_string()
            }
        );
    }

    #[test]
    fn anonymous_is_an_authenticated_outcome_and_not_a_skipped_gate() {
        // ADR-0019 clause 2. The claim is "nobody", it is verified as such, and
        // authorization then decides whether nobody may post here.
        let identity = authenticate(
            &Acceptance::closed().accepting(&mechanism::anonymous()),
            &[&Always(mechanism::anonymous(), Verified::Proven)],
            &registry(),
            &Presented::new(mechanism::anonymous(), ""),
        )
        .expect("accepted");

        assert_eq!(identity.verified, Verified::Proven);
    }

    #[test]
    fn a_claim_with_no_cryptography_is_recorded_as_claimed() {
        // X12 over a drop folder. It passes the gate and it does not pretend to
        // have been proven.
        let identity = authenticate(
            &Acceptance::closed().accepting(&mechanism::edi_x12_interchange()),
            &[&Always(
                mechanism::edi_x12_interchange(),
                Verified::Claimed,
            )],
            &registry(),
            &Presented::new(mechanism::edi_x12_interchange(), "ISA06=PARTNERX"),
        )
        .expect("accepted");

        assert_eq!(identity.verified, Verified::Claimed);
    }

    #[test]
    fn evidence_from_the_transport_reaches_the_record() {
        let identity = authenticate(
            &Acceptance::closed().accepting(&mechanism::mutual_tls()),
            &[&tls_proves()],
            &registry(),
            &Presented::new(mechanism::mutual_tls(), "CN=partner-x.example")
                .with_evidence("issuer", "CN=Example CA")
                .with_evidence("source", "203.0.113.7"),
        )
        .expect("accepted");

        assert_eq!(identity.evidence.len(), 2);
    }
}
