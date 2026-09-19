//! What an authenticator concluded, and what it learned by concluding it.
//!
//! Some mechanisms know the real name only once the proof has held: a
//! Kerberos ticket seals its client until the service key opens it, and an
//! opaque token says nothing until the authorization server is asked. The
//! first gate cannot write that name, because it verifies nothing, and
//! [`Verified`] alone has no room for it. A [`Conclusion`] carries both: the
//! verdict, and the pairs of evidence the verifying itself gave (ADR-0054).
//!
//! What is learned is the mechanism's own word, covered by its proof, so on
//! the identity it takes the place of a presented pair of the same name: a
//! claimed `principal.user` does not stand beside a verified one.

use context::Verified;

/// The evidence name a token's scopes are learned under: the space-separated
/// list as the token or its authorization server stated it (RFC 6749 section
/// 3.3). `authorize/scope` reads this name and nothing else.
pub const SCOPE: &str = "scope";

/// A verdict, and the evidence learned in reaching it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Conclusion {
    /// What the mechanism concluded about the claim.
    pub verified: Verified,
    /// Evidence the verifying gave and the claim could not: a ticket's
    /// client, a token's scopes. Named as the first gate names evidence.
    pub learned: Vec<(String, String)>,
}

impl Conclusion {
    /// The verdict alone, nothing learned.
    #[must_use]
    pub const fn of(verified: Verified) -> Self {
        Self {
            verified,
            learned: Vec::new(),
        }
    }

    /// Proven, nothing learned yet.
    #[must_use]
    pub const fn proven() -> Self {
        Self::of(Verified::Proven)
    }

    /// And this was learned by verifying.
    #[must_use]
    pub fn learning(mut self, name: impl Into<String>, value: impl Into<String>) -> Self {
        self.learned.push((name.into(), value.into()));
        self
    }

    /// Whether verifying gave a pair of this name.
    #[must_use]
    pub fn learned(&self, name: &str) -> Option<&str> {
        self.learned
            .iter()
            .find(|(learned, _)| learned == name)
            .map(|(_, value)| value.as_str())
    }
}

impl From<Verified> for Conclusion {
    fn from(verified: Verified) -> Self {
        Self::of(verified)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_verdict_alone_learned_nothing_and_a_learned_pair_is_found_by_name() {
        assert!(Conclusion::from(Verified::Claimed).learned.is_empty());

        let conclusion = Conclusion::proven().learning("principal.user", "jane@corp.example");
        assert_eq!(conclusion.verified, Verified::Proven);
        assert_eq!(
            conclusion.learned("principal.user"),
            Some("jane@corp.example")
        );
        assert_eq!(conclusion.learned("oauth2.scope"), None);
    }
}
