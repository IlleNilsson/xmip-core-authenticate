//! The account a claim names, said once for every verifier of a user's
//! password: which claims such a verifier reads, and that a claim's
//! `principal.user` evidence names the same account it presents.

use identify::Presented;
use identify::evidence::PRINCIPAL_USER;
use identify::principal::UserPrincipalName;
use xcore::Mechanism;
use xcore::mechanism::USERNAME;

use crate::AuthenticateError;

/// Refuse a claim a verifier of a user's password does not read: one filed
/// under `own`, or a bare user name the first gate filed under
/// [`USERNAME`], is its; anything else is another mechanism's.
///
/// # Errors
///
/// Another mechanism's claim, named.
pub fn user_claim(presented: &Presented, own: &Mechanism) -> Result<(), AuthenticateError> {
    let name = presented.mechanism.name();
    if name == USERNAME || name == own.name() {
        return Ok(());
    }
    Err(AuthenticateError::new(format!(
        "'{name}' is not a claim the {} verifier reads: it takes a username",
        own.name()
    )))
}

/// The account a claim's `principal.user` evidence names, where it is a
/// user principal name.
#[must_use]
pub fn evidenced(presented: &Presented) -> Option<UserPrincipalName> {
    presented
        .evidence(PRINCIPAL_USER)
        .and_then(UserPrincipalName::parse)
}

/// Refuse a claim whose `principal.user` evidence names another account than
/// `read`, the one the verifier read the claim as. Evidence is never proof:
/// agreeing with it proves nothing, and the verifier still decides.
///
/// # Errors
///
/// The two accounts, named.
pub fn same_account(
    presented: &Presented,
    read: &UserPrincipalName,
) -> Result<(), AuthenticateError> {
    match evidenced(presented) {
        Some(claimed) if !claimed.is(read) => Err(AuthenticateError::new(format!(
            "the claim presents '{read}' and its evidence names '{claimed}': not the same account"
        ))),
        _ => Ok(()),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use xcore::mechanism;

    fn claim(value: &str) -> Presented {
        Presented::passed(mechanism::username(), value)
    }

    #[test]
    fn a_password_verifier_reads_its_own_claim_and_a_bare_user_name_only() {
        let ldap = mechanism::ldap();
        assert!(user_claim(&claim("jane"), &ldap).is_ok());
        assert!(user_claim(&Presented::passed(mechanism::ldap(), "jane"), &ldap).is_ok());
        let other = user_claim(&Presented::passed(mechanism::bearer(), "jane"), &ldap)
            .expect_err("another mechanism's claim");
        assert!(other.message.contains("'bearer'"), "{other}");
    }

    #[test]
    fn evidence_naming_another_account_is_refused_and_any_spelling_of_the_same_is_not() {
        let read = UserPrincipalName::parse("jane@partyx").expect("a principal");
        let same = claim("jane").with_evidence(PRINCIPAL_USER, "PARTYX\\jane");
        let other = claim("jane").with_evidence(PRINCIPAL_USER, "mallory@partyx");
        assert!(same_account(&same, &read).is_ok());
        assert!(same_account(&claim("jane"), &read).is_ok());
        let refused = same_account(&other, &read).expect_err("another account");
        assert!(
            refused.message.contains("not the same account"),
            "{refused}"
        );
    }
}
