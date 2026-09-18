//! An X.509 chain, read and walked to a trust anchor the node holds.
//!
//! What `certificate` and `mutual-tls` both need lives here, in their
//! capability (ADR-0044), behind the `x509` feature so that a technology
//! that never sees a certificate never carries this. A chain arrives as the
//! transport reported it — PEM, leaf first — and is verified as ADR-0033
//! says: the path reaches one of the anchors the node was configured with,
//! every certificate on it is inside its validity window now, and none is on
//! a revocation list the node holds. Revocation is by CRL and offline
//! (ADR-0045); asking an OCSP responder is online and waits for the switch.
//!
//! webpki walks the path and checks the signatures; it keeps names as DER,
//! so [`Name`] reads the subject and the alternative names with x509-parser.

pub mod name;
pub mod revocation;

#[cfg(feature = "mint")]
pub mod mint;

pub use name::Name;
pub use revocation::Revocation;

use crate::AuthenticateError;
use rustls_pki_types::{CertificateDer, UnixTime};
use sha2::{Digest, Sha256};
use std::time::Duration;
use webpki::{EndEntityCert, ExtendedKeyUsageValidator, KeyPurposeIdIter, KeyUsage};

/// A chain as the peer sent it: the leaf first, then whatever intermediates
/// came with it, and never the anchor.
#[derive(Clone, Debug)]
pub struct Chain {
    certificates: Vec<CertificateDer<'static>>,
}

impl Chain {
    /// Read PEM, leaf first. Refuses text with no `CERTIFICATE` block.
    ///
    /// # Errors
    ///
    /// The text holds no certificate, or a block in it is not one.
    pub fn from_pem(pem: &str) -> Result<Self, AuthenticateError> {
        let certificates = read_pem(pem, |rd| rustls_pemfile::certs(rd).collect())?;

        if certificates.is_empty() {
            return Err(AuthenticateError::new(
                "the chain holds no certificate: no CERTIFICATE block in the PEM",
            ));
        }

        Ok(Self { certificates })
    }

    /// The certificate the peer is: the first one.
    #[must_use]
    pub fn leaf(&self) -> &CertificateDer<'static> {
        &self.certificates[0]
    }

    /// The certificates between the leaf and an anchor, in the order sent.
    #[must_use]
    pub fn intermediates(&self) -> &[CertificateDer<'static>] {
        &self.certificates[1..]
    }

    /// The leaf's SHA-256 fingerprint, `SHA256:` then lowercase hex, the way
    /// the transport reports it beside the subject.
    #[must_use]
    pub fn fingerprint(&self) -> String {
        let digest = Sha256::digest(self.leaf().as_ref());
        let mut text = String::with_capacity(7 + digest.len() * 2);
        text.push_str("SHA256:");

        for byte in digest {
            text.push_str(&format!("{byte:02x}"));
        }

        text
    }
}

/// The trust anchors a node holds: the certificates a chain must reach.
#[derive(Clone, Debug, Default)]
pub struct Anchors {
    certificates: Vec<CertificateDer<'static>>,
}

impl Anchors {
    /// Read every `CERTIFICATE` block in the PEM as an anchor.
    ///
    /// # Errors
    ///
    /// A block is not a certificate.
    pub fn from_pem(pem: &str) -> Result<Self, AuthenticateError> {
        Ok(Self {
            certificates: read_pem(pem, |rd| rustls_pemfile::certs(rd).collect())?,
        })
    }

    /// Whether the node holds no anchor at all, which is a refusal waiting to
    /// happen and is said so before any chain is looked at.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.certificates.is_empty()
    }

    /// How many anchors the node holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.certificates.len()
    }
}

/// What the leaf must be for, by its extended key usage.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Usage {
    /// A client authenticating to the node: the extension, where present,
    /// names `clientAuth`. What `mutual-tls` requires.
    #[default]
    ClientAuth,
    /// Any purpose. An S/MIME certificate in AS2 names `emailProtection` and
    /// an OPC UA instance certificate names what its profile says, so the
    /// `certificate` mechanism decides usage by configuration.
    Any,
}

impl ExtendedKeyUsageValidator for Usage {
    fn validate(&self, iter: KeyPurposeIdIter<'_, '_>) -> Result<(), webpki::Error> {
        match self {
            Self::ClientAuth => KeyUsage::client_auth().validate(iter),
            Self::Any => Ok(()),
        }
    }
}

/// Walk the chain to one of the anchors, at `now` (seconds since the Unix
/// epoch), for `usage`, against the revocation lists where given. Answers
/// nothing on success; every refusal names its reason in words an operator
/// can act on.
///
/// # Errors
///
/// No anchor is held, the chain reaches none of them, a certificate is
/// outside its validity window, revoked, or not for the usage asked.
pub fn verify(
    chain: &Chain,
    anchors: &Anchors,
    usage: Usage,
    revocation: Option<&Revocation>,
    now: i64,
) -> Result<(), AuthenticateError> {
    if anchors.is_empty() {
        return Err(AuthenticateError::new(
            "the node holds no trust anchor, so no chain can be verified",
        ));
    }

    let anchors = anchors
        .certificates
        .iter()
        .map(|certificate| {
            webpki::anchor_from_trusted_cert(certificate).map_err(|failure| {
                AuthenticateError::new(format!("a configured trust anchor is not one: {failure}"))
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let leaf = EndEntityCert::try_from(chain.leaf())
        .map_err(|failure| AuthenticateError::new(format!("the leaf is not X.509: {failure}")))?;
    let time = UnixTime::since_unix_epoch(Duration::from_secs(now.max(0).unsigned_abs()));
    let lists = revocation.map(Revocation::parsed).transpose()?;
    let references: Option<Vec<&webpki::CertRevocationList<'_>>> =
        lists.as_ref().map(|lists| lists.iter().collect());
    let options = references.as_deref().map(Revocation::options).transpose()?;

    leaf.verify_for_usage(
        webpki::ALL_VERIFICATION_ALGS,
        &anchors,
        chain.intermediates(),
        time,
        usage,
        options,
        None,
    )
    .map(|_| ())
    .map_err(|failure| AuthenticateError::new(said(&failure)))
}

/// The refusal in words, for the reasons an operator meets.
fn said(failure: &webpki::Error) -> String {
    match failure {
        webpki::Error::CertExpired { .. } => "the certificate has expired".to_string(),
        webpki::Error::CertNotValidYet { .. } => "the certificate is not yet valid".to_string(),
        webpki::Error::UnknownIssuer => {
            "the chain reaches no trust anchor this node holds".to_string()
        }
        webpki::Error::CertRevoked => "the certificate is revoked".to_string(),
        webpki::Error::UnknownRevocationStatus => {
            "no revocation list the node holds covers the certificate".to_string()
        }
        webpki::Error::RequiredEkuNotFoundContext(_) => {
            "the certificate is not for client authentication".to_string()
        }
        other => format!("the chain does not verify: {other}"),
    }
}

/// Every block of one kind in a PEM text, read with one of rustls-pemfile's
/// readers, and the error said in words where a block is not what it claims.
fn read_pem<T>(
    pem: &str,
    reader: impl FnOnce(&mut dyn std::io::BufRead) -> Result<Vec<T>, std::io::Error>,
) -> Result<Vec<T>, AuthenticateError> {
    let mut cursor = std::io::BufReader::new(pem.as_bytes());

    reader(&mut cursor)
        .map_err(|failure| AuthenticateError::new(format!("the PEM does not read: {failure}")))
}

#[cfg(test)]
mod tests {
    use super::mint::Authority;
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    #[test]
    fn a_chain_to_a_held_anchor_verifies_and_the_fingerprint_is_the_leafs() {
        let root = Authority::root("Partner Root");
        let issuing = root.intermediate("Partner Issuing CA");
        let issued = issuing.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");

        verify(&chain, &anchors, Usage::ClientAuth, None, NOW).expect("verified");
        assert_eq!(chain.intermediates().len(), 1);
        assert!(chain.fingerprint().starts_with("SHA256:"));
        assert_eq!(chain.fingerprint().len(), 7 + 64);
    }

    #[test]
    fn a_chain_to_an_anchor_the_node_does_not_hold_is_refused_saying_so() {
        let root = Authority::root("Partner Root");
        let stranger = Authority::root("Somebody Else");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let anchors = Anchors::from_pem(&stranger.pem()).expect("anchors");

        let failure = verify(&chain, &anchors, Usage::ClientAuth, None, NOW).expect_err("refused");
        assert!(failure.message.contains("no trust anchor"), "{failure}");
    }

    #[test]
    fn an_expired_certificate_is_refused_by_the_clock_it_is_given() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - 2 * DAY, NOW - DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");

        let failure = verify(&chain, &anchors, Usage::ClientAuth, None, NOW).expect_err("refused");
        assert!(failure.message.contains("expired"), "{failure}");
        verify(&chain, &anchors, Usage::ClientAuth, None, NOW - DAY - 1).expect("was valid then");
    }

    #[test]
    fn no_anchor_held_is_said_before_any_chain_is_read() {
        let root = Authority::root("Partner Root");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");

        let failure =
            verify(&chain, &Anchors::default(), Usage::ClientAuth, None, NOW).expect_err("refused");
        assert!(failure.message.contains("no trust anchor"), "{failure}");
    }

    #[test]
    fn text_with_no_certificate_block_is_not_a_chain() {
        let failure = Chain::from_pem("MIIB").expect_err("not a chain");
        assert!(
            failure.message.contains("no CERTIFICATE block"),
            "{failure}"
        );
    }
}
