//! What a signed credential says of itself, held to what the node expects:
//! who issued it, whom it is for, and until when it holds.
//!
//! A JWT's `iss`, `aud` and `exp`, an ID token's the same, an introspection
//! answer's the same again, and an assertion's `Issuer`, `Audience` and
//! `NotOnOrAfter`: four technologies ask the same three questions, and each
//! asked them in words and rules of its own, one of which let a token with
//! no `exp` through for ever. The rules are here and every one of them
//! calls these.
//!
//! The issuer and the audience are configuration and required: an
//! [`Expected`] cannot be made without both, so a verifier cannot be built
//! that takes a token from anyone, for anyone. The expiry is required of
//! the credential with [`current`]; [`within`] is for an answer whose
//! window is optional by its standard, as RFC 7662 makes an introspection
//! response's `exp`.

use crate::AuthenticateError;
use crate::clock::{Clock, Window};

/// The issuer a credential must name and the audience it must be for.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Expected {
    issuer: String,
    audience: String,
}

impl Expected {
    /// A credential from `issuer`, for `audience`.
    ///
    /// # Errors
    ///
    /// Where either is empty: a check against nothing is no check.
    pub fn new(
        issuer: impl Into<String>,
        audience: impl Into<String>,
    ) -> Result<Self, AuthenticateError> {
        let (issuer, audience) = (issuer.into(), audience.into());
        if issuer.trim().is_empty() || audience.trim().is_empty() {
            return Err(AuthenticateError::new(
                "a verifier needs the issuer and the audience it expects, and one is empty",
            ));
        }
        Ok(Self { issuer, audience })
    }

    /// The issuer expected.
    #[must_use]
    pub fn issuer(&self) -> &str {
        &self.issuer
    }

    /// The audience expected.
    #[must_use]
    pub fn audience(&self) -> &str {
        &self.audience
    }

    /// `what` — *the token*, *the assertion* — names the issuer expected.
    ///
    /// # Errors
    ///
    /// Where it names none or another.
    pub fn issued(&self, what: &str, named: Option<&str>) -> Result<(), AuthenticateError> {
        issued_by(what, named, &self.issuer)
    }

    /// `what` names the audience expected among `named`.
    ///
    /// # Errors
    ///
    /// Where none of `named` is it.
    pub fn addressed<'a>(
        &self,
        what: &str,
        named: impl IntoIterator<Item = &'a str>,
    ) -> Result<(), AuthenticateError> {
        addressed_to(what, named, &self.audience)
    }
}

/// `what` names `issuer`.
///
/// # Errors
///
/// Where it names none or another.
pub fn issued_by(what: &str, named: Option<&str>, issuer: &str) -> Result<(), AuthenticateError> {
    if named == Some(issuer) {
        return Ok(());
    }
    Err(AuthenticateError::new(format!(
        "{what}'s issuer is not '{issuer}'"
    )))
}

/// `what` names `audience` among `named`.
///
/// # Errors
///
/// Where none of `named` is it.
pub fn addressed_to<'a>(
    what: &str,
    named: impl IntoIterator<Item = &'a str>,
    audience: &str,
) -> Result<(), AuthenticateError> {
    if named.into_iter().any(|one| one == audience) {
        return Ok(());
    }
    Err(AuthenticateError::new(format!(
        "{what}'s audience does not name '{audience}'"
    )))
}

/// `what` carries an expiry, `expiry` by the name its standard gives it,
/// and the clock lies inside its window.
///
/// # Errors
///
/// Where it carries no expiry, or the clock lies outside the window.
pub fn current(
    what: &str,
    clock: &Clock,
    not_before: Option<i64>,
    expiry: (&str, Option<i64>),
) -> Result<(), AuthenticateError> {
    let (name, expires) = expiry;
    let Some(expires) = expires else {
        return Err(AuthenticateError::new(format!(
            "{what} carries no `{name}`, and a credential without an expiry is refused"
        )));
    };
    within(what, clock, Window::between(not_before, Some(expires)))
}

/// The clock lies inside `window`, either end of which may be open.
///
/// # Errors
///
/// Where it lies outside, saying which end.
pub fn within(what: &str, clock: &Clock, window: Window) -> Result<(), AuthenticateError> {
    clock
        .admits(window)
        .map_err(|outside| AuthenticateError::new(format!("{what} {outside}")))
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn clock() -> Clock {
        Clock::system(0).reading(|| NOW)
    }

    #[test]
    fn an_expectation_needs_both_an_issuer_and_an_audience() {
        assert!(Expected::new("", "xmip").is_err());
        assert!(Expected::new("https://issuer.example", " ").is_err());
        let expected = Expected::new("https://issuer.example", "xmip").expect("both");
        assert_eq!(
            (expected.issuer(), expected.audience()),
            ("https://issuer.example", "xmip")
        );
    }

    #[test]
    fn another_issuer_or_audience_is_refused_naming_the_one_expected() {
        let expected = Expected::new("https://issuer.example", "xmip").expect("both");

        expected
            .issued("the token", Some("https://issuer.example"))
            .expect("the issuer expected");
        let issuer = expected.issued("the token", None).expect_err("none");
        let audience = expected
            .addressed("the assertion", ["other", "else"])
            .expect_err("another");

        assert_eq!(
            issuer.message,
            "the token's issuer is not 'https://issuer.example'"
        );
        assert_eq!(
            audience.message,
            "the assertion's audience does not name 'xmip'"
        );
        expected
            .addressed("the token", ["other", "xmip"])
            .expect("one of them is the audience");
    }

    #[test]
    fn a_credential_without_an_expiry_is_refused_and_one_past_it_is_too() {
        let missing = current("the token", &clock(), None, ("exp", None)).expect_err("no exp");
        let late = current("the token", &clock(), None, ("exp", Some(NOW))).expect_err("late");

        assert_eq!(
            missing.message,
            "the token carries no `exp`, and a credential without an expiry is refused"
        );
        assert_eq!(
            late.message,
            "the token expired at 1800000000 and it is 1800000000"
        );
        current("the token", &clock(), Some(NOW), ("exp", Some(NOW + 1))).expect("current");
        within("the answer", &clock(), Window::default()).expect("an open window");
    }
}
