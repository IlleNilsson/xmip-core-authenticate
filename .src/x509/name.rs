//! Whether a certificate names what was claimed.
//!
//! The first gate presents the subject the transport reported —
//! `CN=party-x.example,O=Party X` — and the second gate must find the
//! same name in the leaf it verified: as its subject, compared attribute by
//! attribute in any order ([`Name`], `xmip-core-library-tls`'s, which the
//! transport wrote the subject with), as one of the DNS names its
//! alternative names carry, or as the user principal name a smart-card
//! certificate carries.

use crate::AuthenticateError;
use identify::UserPrincipalName;
use rustls_pki_types::CertificateDer;
use tls::Name;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate};

/// The subject of a certificate.
///
/// # Errors
///
/// The bytes are not an X.509 certificate.
pub fn subject_of(certificate: &CertificateDer<'_>) -> Result<Name, AuthenticateError> {
    Name::subject_of(certificate).map_err(|failure| AuthenticateError::new(failure.message))
}

/// The DNS names a certificate's alternative names carry.
///
/// # Errors
///
/// The bytes are not an X.509 certificate, or the extension is malformed.
pub fn dns_names_of(certificate: &CertificateDer<'_>) -> Result<Vec<String>, AuthenticateError> {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|failure| AuthenticateError::new(format!("not X.509: {failure}")))?;
    let alternative = parsed.subject_alternative_name().map_err(|failure| {
        AuthenticateError::new(format!("the alternative names do not read: {failure}"))
    })?;

    Ok(alternative
        .into_iter()
        .flat_map(|extension| extension.value.general_names.iter())
        .filter_map(|name| match name {
            GeneralName::DNSName(dns) => Some((*dns).to_string()),
            _ => None,
        })
        .collect())
}

/// The user principal name a certificate carries, where it carries one:
/// the subjectAltName otherName under Microsoft's UPN object identifier,
/// 1.3.6.1.4.1.311.20.2.3, which is how a smart-card logon certificate
/// says whose it is (ADR-0054).
///
/// # Errors
///
/// The bytes are not an X.509 certificate, or the extension is malformed.
pub fn user_principal_of(
    certificate: &CertificateDer<'_>,
) -> Result<Option<UserPrincipalName>, AuthenticateError> {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|failure| AuthenticateError::new(format!("not X.509: {failure}")))?;
    let alternative = parsed.subject_alternative_name().map_err(|failure| {
        AuthenticateError::new(format!("the alternative names do not read: {failure}"))
    })?;

    Ok(alternative
        .into_iter()
        .flat_map(|extension| extension.value.general_names.iter())
        .find_map(|name| match name {
            GeneralName::OtherName(kind, value) if kind.to_id_string() == UPN => {
                utf8_within(value).and_then(|text| UserPrincipalName::parse(&text))
            }
            _ => None,
        }))
}

/// Whether a certificate names the claim: as its subject, as one of its
/// DNS names, or, where the claim is a user principal name, as the same
/// account the certificate carries one for.
///
/// # Errors
///
/// The bytes are not an X.509 certificate.
pub fn names(certificate: &CertificateDer<'_>, claim: &str) -> Result<bool, AuthenticateError> {
    if subject_of(certificate)? == Name::parse(claim) {
        return Ok(true);
    }

    if let Some(claimed) = UserPrincipalName::parse(claim)
        && let Some(carried) = user_principal_of(certificate)?
    {
        return Ok(carried.is(&claimed));
    }

    Ok(dns_names_of(certificate)?
        .iter()
        .any(|dns| dns.eq_ignore_ascii_case(claim.trim())))
}

/// Microsoft's object identifier for a user principal name in an otherName.
const UPN: &str = "1.3.6.1.4.1.311.20.2.3";

/// The text of an otherName value: `[0] EXPLICIT UTF8String`, two headers
/// and a string read by the estate's X.690 reader (`xmip-core-library-asn1`),
/// which this file read again, two length bytes at most, until 2026-09-28.
fn utf8_within(value: &[u8]) -> Option<String> {
    let (inner, _) = asn1::expect(value, 0xA0).ok()?;
    let (text, _) = asn1::expect(inner, 0x0C).ok()?;

    String::from_utf8(text.to_vec()).ok()
}

#[cfg(test)]
mod tests {
    use super::super::mint::Authority;
    use super::*;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn a_smart_card_certificate_names_its_user_in_either_spelling() {
        let root = Authority::root("Party Root");
        let issued = root.issue_for_user("jane", "Jane@Party-X.Example", NOW - 10, NOW + 10);
        let chain = super::super::Chain::from_pem(&issued.pem).expect("a chain");

        let carried = user_principal_of(chain.leaf())
            .expect("read")
            .expect("a user principal name");
        assert_eq!(carried.to_string(), "Jane@party-x.example");
        assert!(names(chain.leaf(), "jane@party-x.example").expect("read"));
        assert!(names(chain.leaf(), "PARTY-X.EXAMPLE\\JANE").expect("read"));
        assert!(!names(chain.leaf(), "john@party-x.example").expect("read"));

        let plain = root.issue("party-x.example", NOW - 10, NOW + 10);
        let chain = super::super::Chain::from_pem(&plain.pem).expect("a chain");
        assert!(user_principal_of(chain.leaf()).expect("read").is_none());
    }

    #[test]
    fn a_certificate_names_its_subject_and_its_dns_names_and_nothing_else() {
        let root = Authority::root("Party Root");
        let issued = root.issue("party-x.example", NOW - 10, NOW + 10);
        let chain = super::super::Chain::from_pem(&issued.pem).expect("a chain");

        assert_eq!(
            subject_of(chain.leaf()).expect("a subject").to_string(),
            "CN=party-x.example,O=Party X"
        );
        assert!(names(chain.leaf(), "O=Party X,CN=party-x.example").expect("read"));
        assert!(names(chain.leaf(), "PARTY-X.example").expect("read"));
        assert!(!names(chain.leaf(), "CN=party-y.example").expect("read"));
    }
}
