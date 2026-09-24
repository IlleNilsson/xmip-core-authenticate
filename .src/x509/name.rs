//! A distinguished name as the estate writes it, and whether a certificate
//! names what was claimed.
//!
//! The first gate presents the subject the transport reported —
//! `CN=partner-x.example,O=Partner X` — and the second gate must find the
//! same name in the leaf it verified. Two writers render one name two ways:
//! RFC 4514 reverses the order and OpenSSL keeps it, one puts a space after
//! the comma and the other does not. So a name here is its attributes, and
//! two names are the same when they hold the same attributes, in any order.
//! A claim may also be a DNS name the leaf's alternative names carry.

use crate::AuthenticateError;
use identify::UserPrincipalName;
use rustls_pki_types::CertificateDer;
use std::fmt;
use x509_parser::extensions::GeneralName;
use x509_parser::prelude::{FromDer, X509Certificate, X509Name};

/// A distinguished name: its attributes, type and value.
#[derive(Clone, Debug, Default, Eq, PartialEq)]
pub struct Name {
    attributes: Vec<(String, String)>,
}

impl Name {
    /// Parse `TYPE=value,TYPE=value`. A comma inside a value is escaped with
    /// a backslash, as RFC 4514 writes it. Types are compared without case.
    #[must_use]
    pub fn parse(text: &str) -> Self {
        let mut attributes = Vec::new();
        let mut part = String::new();
        let mut escaped = false;

        for character in text.chars() {
            match (escaped, character) {
                (false, '\\') => escaped = true,
                (false, ',') => {
                    push(&mut attributes, &part);
                    part.clear();
                }
                (_, character) => {
                    escaped = false;
                    part.push(character);
                }
            }
        }

        push(&mut attributes, &part);
        Self { attributes }
    }

    /// The subject of a certificate.
    ///
    /// # Errors
    ///
    /// The bytes are not an X.509 certificate.
    pub fn subject_of(certificate: &CertificateDer<'_>) -> Result<Self, AuthenticateError> {
        let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
            .map_err(|failure| AuthenticateError::new(format!("not X.509: {failure}")))?;

        Ok(Self::of(parsed.subject()))
    }

    /// The DNS names a certificate's alternative names carry.
    ///
    /// # Errors
    ///
    /// The bytes are not an X.509 certificate, or the extension is malformed.
    pub fn dns_names_of(
        certificate: &CertificateDer<'_>,
    ) -> Result<Vec<String>, AuthenticateError> {
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
        if Self::subject_of(certificate)? == Self::parse(claim) {
            return Ok(true);
        }

        if let Some(claimed) = UserPrincipalName::parse(claim)
            && let Some(carried) = Self::user_principal_of(certificate)?
        {
            return Ok(carried.is(&claimed));
        }

        Ok(Self::dns_names_of(certificate)?
            .iter()
            .any(|dns| dns.eq_ignore_ascii_case(claim.trim())))
    }

    /// Whether the name is empty.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.attributes.is_empty()
    }

    fn of(subject: &X509Name<'_>) -> Self {
        let mut attributes: Vec<(String, String)> = subject
            .iter()
            .flat_map(|rdn| rdn.iter())
            .map(|attribute| {
                let value = attribute.as_str().map_or_else(
                    |_| format!("#{}", codec::hex::encode(attribute.attr_value().data)),
                    ToString::to_string,
                );
                (short(&attribute.attr_type().to_id_string()), value)
            })
            .collect();
        attributes.sort();

        Self { attributes }
    }
}

impl fmt::Display for Name {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (index, (kind, value)) in self.attributes.iter().enumerate() {
            if index > 0 {
                f.write_str(",")?;
            }

            write!(f, "{kind}={}", value.replace(',', "\\,"))?;
        }

        Ok(())
    }
}

/// Microsoft's object identifier for a user principal name in an otherName.
const UPN: &str = "1.3.6.1.4.1.311.20.2.3";

/// The text of an otherName value: `[0] EXPLICIT UTF8String`, read without a
/// DER library because it is two headers and a string.
fn utf8_within(value: &[u8]) -> Option<String> {
    let inner = contents(value, 0xA0)?;
    let text = contents(inner, 0x0C)?;

    String::from_utf8(text.to_vec()).ok()
}

/// The contents of one DER element with the tag expected, short or long
/// length, where the bytes hold all of it.
fn contents(bytes: &[u8], tag: u8) -> Option<&[u8]> {
    let (&found, rest) = bytes.split_first()?;
    let (&first, rest) = rest.split_first()?;

    if found != tag {
        return None;
    }

    let (length, rest) = if first < 0x80 {
        (usize::from(first), rest)
    } else {
        let count = usize::from(first & 0x7F);

        if count == 0 || count > 2 || rest.len() < count {
            return None;
        }

        let length = rest[..count]
            .iter()
            .fold(0usize, |length, &byte| (length << 8) | usize::from(byte));
        (length, &rest[count..])
    };

    rest.get(..length)
}

fn push(attributes: &mut Vec<(String, String)>, part: &str) {
    let part = part.trim();

    if part.is_empty() {
        return;
    }

    let (kind, value) = part.split_once('=').unwrap_or((part, ""));
    attributes.push((short(kind.trim()).to_uppercase(), value.trim().to_string()));
    attributes.sort();
}

/// The short name for the attribute types a subject commonly carries; a
/// dotted OID stands for the rest, and a short name already given stays.
fn short(kind: &str) -> String {
    match kind {
        "2.5.4.3" => "CN",
        "2.5.4.4" => "SN",
        "2.5.4.5" => "SERIALNUMBER",
        "2.5.4.6" => "C",
        "2.5.4.7" => "L",
        "2.5.4.8" => "ST",
        "2.5.4.9" => "STREET",
        "2.5.4.10" => "O",
        "2.5.4.11" => "OU",
        "2.5.4.12" => "TITLE",
        "2.5.4.42" => "GN",
        "0.9.2342.19200300.100.1.1" => "UID",
        "0.9.2342.19200300.100.1.25" => "DC",
        "1.2.840.113549.1.9.1" => "EMAILADDRESS",
        other => return other.to_uppercase(),
    }
    .to_string()
}

#[cfg(test)]
mod tests {
    use super::super::mint::Authority;
    use super::*;

    const NOW: i64 = 1_800_000_000;

    #[test]
    fn the_same_attributes_in_either_order_and_spacing_are_one_name() {
        let ours = Name::parse("CN=partner-x.example,O=Partner X");
        let theirs = Name::parse("O = Partner X, cn = partner-x.example");

        assert_eq!(ours, theirs);
        assert_eq!(ours.to_string(), "CN=partner-x.example,O=Partner X");
    }

    #[test]
    fn a_comma_in_a_value_is_escaped_and_survives() {
        let name = Name::parse("CN=Partner\\, Inc,O=Partner X");

        assert_eq!(name.to_string(), "CN=Partner\\, Inc,O=Partner X");
        assert_ne!(name, Name::parse("CN=Partner,O=Partner X"));
    }

    #[test]
    fn a_smart_card_certificate_names_its_user_in_either_spelling() {
        let root = Authority::root("Partner Root");
        let issued = root.issue_for_user("jane", "Jane@Partner-X.Example", NOW - 10, NOW + 10);
        let chain = super::super::Chain::from_pem(&issued.pem).expect("a chain");

        let carried = Name::user_principal_of(chain.leaf())
            .expect("read")
            .expect("a user principal name");
        assert_eq!(carried.to_string(), "Jane@partner-x.example");
        assert!(Name::names(chain.leaf(), "jane@partner-x.example").expect("read"));
        assert!(Name::names(chain.leaf(), "PARTNER-X.EXAMPLE\\JANE").expect("read"));
        assert!(!Name::names(chain.leaf(), "john@partner-x.example").expect("read"));

        let plain = root.issue("partner-x.example", NOW - 10, NOW + 10);
        let chain = super::super::Chain::from_pem(&plain.pem).expect("a chain");
        assert!(
            Name::user_principal_of(chain.leaf())
                .expect("read")
                .is_none()
        );
    }

    #[test]
    fn a_certificate_names_its_subject_and_its_dns_names_and_nothing_else() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - 10, NOW + 10);
        let chain = super::super::Chain::from_pem(&issued.pem).expect("a chain");

        assert_eq!(
            Name::subject_of(chain.leaf())
                .expect("a subject")
                .to_string(),
            "CN=partner-x.example,O=Partner X"
        );
        assert!(Name::names(chain.leaf(), "O=Partner X,CN=partner-x.example").expect("read"));
        assert!(Name::names(chain.leaf(), "PARTNER-X.example").expect("read"));
        assert!(!Name::names(chain.leaf(), "CN=partner-y.example").expect("read"));
    }
}
