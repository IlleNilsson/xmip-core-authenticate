//! The revocation lists a node holds.
//!
//! Revocation here is by CRL and offline (ADR-0045): the lists are
//! configuration the node was given, read once, and a certificate on any of
//! them is refused. A list that names no issuer on the path is not consulted,
//! and a certificate whose issuer published no list the node holds is
//! refused as of unknown status rather than let through: where an operator
//! configured revocation at all, silence is not a pass. Asking an OCSP
//! responder is online and is not built until the `online` switch says so.

use crate::AuthenticateError;
use rustls_pki_types::CertificateRevocationListDer;
use webpki::{
    CertRevocationList, OwnedCertRevocationList, RevocationCheckDepth, RevocationOptions,
    RevocationOptionsBuilder, UnknownStatusPolicy,
};

/// The CRLs a node holds, as their DER.
#[derive(Clone, Debug, Default)]
pub struct Revocation {
    lists: Vec<CertificateRevocationListDer<'static>>,
}

impl Revocation {
    /// Read every `X509 CRL` block in the PEM.
    ///
    /// # Errors
    ///
    /// A block is not a CRL, or none is there.
    pub fn from_pem(pem: &str) -> Result<Self, AuthenticateError> {
        let lists = super::read_pem(pem, |rd| rustls_pemfile::crls(rd).collect())?;

        if lists.is_empty() {
            return Err(AuthenticateError::new(
                "the revocation text holds no list: no X509 CRL block in the PEM",
            ));
        }

        Ok(Self { lists })
    }

    /// How many lists the node holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.lists.len()
    }

    /// Whether no list is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.lists.is_empty()
    }

    /// Every list parsed, so the options can borrow them.
    pub(super) fn parsed(&self) -> Result<Vec<CertRevocationList<'static>>, AuthenticateError> {
        self.lists
            .iter()
            .map(|list| {
                OwnedCertRevocationList::from_der(list.as_ref())
                    .map(CertRevocationList::from)
                    .map_err(|failure| {
                        AuthenticateError::new(format!(
                            "a revocation list does not read: {failure}"
                        ))
                    })
            })
            .collect()
    }

    /// The policy over the parsed lists: the whole chain is checked, and a
    /// certificate no list covers is refused.
    pub(super) fn options<'a>(
        lists: &'a [&'a CertRevocationList<'a>],
    ) -> Result<RevocationOptions<'a>, AuthenticateError> {
        RevocationOptionsBuilder::new(lists)
            .map(|builder| {
                builder
                    .with_depth(RevocationCheckDepth::Chain)
                    .with_status_policy(UnknownStatusPolicy::Deny)
                    .build()
            })
            .map_err(|_| AuthenticateError::new("revocation was asked for and no list is held"))
    }
}

#[cfg(test)]
mod tests {
    use super::super::mint::Authority;
    use super::super::{Anchors, Chain, Usage, verify};
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    #[test]
    fn a_revoked_certificate_is_refused_and_its_neighbour_is_not() {
        let root = Authority::root("Partner Root");
        let revoked = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let fine = root.issue("partner-y.example", NOW - DAY, NOW + DAY);
        let lists = Revocation::from_pem(&root.crl(&[&revoked], NOW)).expect("a list");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");

        let failure = verify(
            &Chain::from_pem(&revoked.pem).expect("a chain"),
            &anchors,
            Usage::ClientAuth,
            Some(&lists),
            NOW,
        )
        .expect_err("revoked");
        assert!(failure.message.contains("revoked"), "{failure}");

        verify(
            &Chain::from_pem(&fine.pem).expect("a chain"),
            &anchors,
            Usage::ClientAuth,
            Some(&lists),
            NOW,
        )
        .expect("not revoked");
    }

    #[test]
    fn an_issuer_with_no_list_held_is_of_unknown_status_and_refused() {
        let root = Authority::root("Partner Root");
        let other = Authority::root("Other Root");
        let issued = root.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let lists = Revocation::from_pem(&other.crl(&[], NOW)).expect("a list");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");

        let failure = verify(
            &Chain::from_pem(&issued.pem).expect("a chain"),
            &anchors,
            Usage::ClientAuth,
            Some(&lists),
            NOW,
        )
        .expect_err("unknown status");
        assert!(failure.message.contains("no revocation list"), "{failure}");
    }

    #[test]
    fn text_with_no_crl_block_is_not_a_revocation_list() {
        let failure = Revocation::from_pem("MIIB").expect_err("not a list");
        assert!(failure.message.contains("no X509 CRL block"), "{failure}");
    }
}
