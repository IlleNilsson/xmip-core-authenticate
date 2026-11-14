//! How long a certificate is valid: the end of its validity window, read
//! once here, for whatever holds an identity a certificate proved no longer
//! than the certificate itself (ADR-0009, amendment 2026-11-01: a caller
//! the operate plane hands out ends where its certificate ends) — and of a
//! verified path, the earliest of its certificates' ends, an
//! intermediate's included (amendment 2026-11-04).

use super::Path;
use crate::AuthenticateError;
use tls::certificate::Certificate;

/// The end of `certificate`'s validity window, `notAfter`, in seconds since
/// the Unix epoch.
///
/// # Errors
///
/// The bytes are not an X.509 certificate.
pub fn not_after_of(certificate: &[u8]) -> Result<i64, AuthenticateError> {
    Certificate::read(certificate)
        .map(|read| read.not_after)
        .map_err(|failure| AuthenticateError::new(format!("not X.509: {failure}")))
}

impl Path {
    /// The earliest end of a validity window along the path — the leaf's,
    /// an intermediate's or the anchor's — in seconds since the Unix epoch:
    /// until when what the path proved holds, so nothing that holds it is
    /// kept past the moment a fresh walk would refuse it.
    ///
    /// # Errors
    ///
    /// A certificate of the path is not X.509.
    pub fn not_after(&self) -> Result<i64, AuthenticateError> {
        self.certificates()
            .iter()
            .map(|certificate| not_after_of(certificate))
            .try_fold(i64::MAX, |earliest, ends| Ok(earliest.min(ends?)))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::mint::Authority;
    use crate::x509::{Anchors, Chain, Usage, verify};

    #[test]
    fn a_path_holds_until_its_first_certificate_ends_an_intermediate_included() {
        let root = Authority::root("validity test root");
        let issuing = root.intermediate_ending("validity test issuing", 1_750_000_000);
        let issued = issuing.issue("alice", 1_700_000_000, 1_800_000_000);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");
        let path =
            verify(&chain, &anchors, Usage::ClientAuth, None, 1_720_000_000).expect("verified");
        assert_eq!(not_after_of(chain.leaf()).expect("read"), 1_800_000_000);
        assert_eq!(path.not_after().expect("read"), 1_750_000_000);
    }

    #[test]
    fn a_certificate_says_when_it_ends_and_bytes_that_are_none_are_refused() {
        let authority = Authority::root("validity test authority");
        let issued = authority.issue("alice", 1_700_000_000, 1_800_000_000);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        assert_eq!(not_after_of(chain.leaf()).expect("read"), 1_800_000_000);
        assert!(not_after_of(&[1u8, 2, 3]).is_err());
    }
}
