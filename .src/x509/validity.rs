//! How long a certificate is valid: the end of its validity window, read
//! once here, for whatever holds an identity a certificate proved no longer
//! than the certificate itself (ADR-0009, amendment 2026-11-01: a caller
//! the operate plane hands out ends where its certificate ends).

use crate::AuthenticateError;
use x509_parser::prelude::{FromDer, X509Certificate};

/// The end of `certificate`'s validity window, `notAfter`, in seconds since
/// the Unix epoch.
///
/// # Errors
///
/// The bytes are not an X.509 certificate.
pub fn not_after_of(certificate: &[u8]) -> Result<i64, AuthenticateError> {
    let (_, parsed) = X509Certificate::from_der(certificate)
        .map_err(|failure| AuthenticateError::new(format!("not X.509: {failure}")))?;
    Ok(parsed.validity().not_after.timestamp())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::x509::Chain;
    use crate::x509::mint::Authority;

    #[test]
    fn a_certificate_says_when_it_ends_and_bytes_that_are_none_are_refused() {
        let authority = Authority::root("validity test authority");
        let issued = authority.issue("alice", 1_700_000_000, 1_800_000_000);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        assert_eq!(not_after_of(chain.leaf()).expect("read"), 1_800_000_000);
        assert!(not_after_of(&[1u8, 2, 3]).is_err());
    }
}
