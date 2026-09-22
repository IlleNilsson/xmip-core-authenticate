//! The alternative signature a hybrid certificate carries, verified along
//! the path the classical walk already proved.
//!
//! ITU-T X.509 (10/2019) clause 9.8 lets one certificate carry two
//! signatures: the classical one where it always was, and in three
//! extensions a second public key (`subjectAltPublicKeyInfo`, 2.5.29.72), the
//! algorithm of a second signature (`altSignatureAlgorithm`, 2.5.29.73) and
//! that signature (`altSignatureValue`, 2.5.29.74), computed over the
//! `tbsCertificate` without its `signature` field and without the
//! `altSignatureValue` extension (clause 7.2.2). A verifier that knows
//! nothing of the extensions sees an ordinary certificate; one that does
//! checks the second signature too. That is the migration ADR-0033's
//! amendment of 2026-09-18 asks for: classical and post-quantum in one
//! certificate, and legacy peers untroubled.
//!
//! The post-quantum algorithm is ML-DSA (FIPS 204), in its three parameter
//! sets, verified by aws-lc-rs, which is why this module is its own feature:
//! ring, beneath the classical walk, has no post-quantum signature.

use super::der;
use super::{Chain, Path};
use crate::AuthenticateError;
use aws_lc_rs::signature::{self, UnparsedPublicKey, VerificationAlgorithm};
use rustls_pki_types::{CertificateDer, alg_id};
use x509_parser::der_parser::oid;
use x509_parser::prelude::{FromDer, X509Certificate};

/// What a node requires of the alternative signatures on a path.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub enum Hybrid {
    /// The extensions are not looked at. A legacy verifier's view.
    Ignored,
    /// A certificate that carries the extensions is verified by them; one
    /// that does not is taken on its classical signature alone. The
    /// migration's middle: a partner may move before the node requires it.
    #[default]
    WherePresent,
    /// Every certificate on the path, the anchor included, carries a valid
    /// alternative signature. Quantum-safe end to end.
    Required,
}

/// One of ML-DSA's three parameter sets, by the algorithm identifier the
/// extension names.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum MlDsa {
    /// ML-DSA-44, id-ml-dsa-44.
    MlDsa44,
    /// ML-DSA-65, id-ml-dsa-65.
    MlDsa65,
    /// ML-DSA-87, id-ml-dsa-87.
    MlDsa87,
}

impl MlDsa {
    /// The set an `AlgorithmIdentifier` names, where it is one of the three.
    fn named(algorithm: &[u8]) -> Option<Self> {
        let (0x30, contents, _) = asn1::read(algorithm).ok()? else {
            return None;
        };

        if contents == alg_id::ML_DSA_44.as_ref() {
            Some(Self::MlDsa44)
        } else if contents == alg_id::ML_DSA_65.as_ref() {
            Some(Self::MlDsa65)
        } else if contents == alg_id::ML_DSA_87.as_ref() {
            Some(Self::MlDsa87)
        } else {
            None
        }
    }

    /// The set's verifier.
    fn verifier(self) -> &'static dyn VerificationAlgorithm {
        match self {
            Self::MlDsa44 => &signature::ML_DSA_44,
            Self::MlDsa65 => &signature::ML_DSA_65,
            Self::MlDsa87 => &signature::ML_DSA_87,
        }
    }

    /// The set's name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::MlDsa44 => "ML-DSA-44",
            Self::MlDsa65 => "ML-DSA-65",
            Self::MlDsa87 => "ML-DSA-87",
        }
    }
}

/// What one certificate carries of the three extensions.
struct Alternative {
    /// The `subjectAltPublicKeyInfo` value: an SPKI, as DER.
    public_key: Option<Vec<u8>>,
    /// The alternative signature and its algorithm, where both are there.
    signature: Option<(MlDsa, Vec<u8>)>,
}

/// Verify the alternative signatures along a path the classical walk
/// proved, from the leaf up to the anchor, under the node's policy.
///
/// # Errors
///
/// A certificate carries an alternative signature that does not verify, or
/// an algorithm this build does not know, or one whose issuer carries no
/// alternative key; or, under `Required`, a certificate carries none.
pub fn verify_alt(path: &Path, hybrid: Hybrid) -> Result<(), AuthenticateError> {
    if hybrid == Hybrid::Ignored {
        return Ok(());
    }

    let certificates = path.certificates();
    let carried = certificates
        .iter()
        .map(|certificate| carried(certificate))
        .collect::<Result<Vec<_>, _>>()?;

    for (index, certificate) in certificates.iter().enumerate() {
        let issuer = &carried[(index + 1).min(certificates.len() - 1)];
        let own = &carried[index];
        let position = position(index, certificates.len());

        match (&own.signature, &issuer.public_key) {
            (None, _) if hybrid == Hybrid::Required => {
                return Err(AuthenticateError::new(format!(
                    "{position} carries no alternative signature and the node requires one"
                )));
            }
            (None, _) => {}
            (Some(_), None) => {
                return Err(AuthenticateError::new(format!(
                    "{position} carries an alternative signature and its issuer no alternative key"
                )));
            }
            (Some((algorithm, value)), Some(public_key)) => {
                let signed = der::pre_tbs(certificate.as_ref())?;
                UnparsedPublicKey::new(algorithm.verifier(), public_key)
                    .verify(&signed, value)
                    .map_err(|_| {
                        AuthenticateError::new(format!(
                            "{position}'s {} alternative signature does not verify",
                            algorithm.name()
                        ))
                    })?;
            }
        }
    }

    Ok(())
}

/// The three extensions off one certificate, read and not yet believed.
fn carried(certificate: &CertificateDer<'_>) -> Result<Alternative, AuthenticateError> {
    let (_, parsed) = X509Certificate::from_der(certificate.as_ref())
        .map_err(|failure| AuthenticateError::new(format!("not X.509: {failure}")))?;
    let extension = |name: &str, id| {
        parsed.get_extension_unique(&id).map_err(|_| {
            AuthenticateError::new(format!("{name} appears more than once in the certificate"))
        })
    };
    let public_key = extension("subjectAltPublicKeyInfo", oid!(2.5.29.72))?
        .map(|extension| extension.value.to_vec());
    let algorithm = extension("altSignatureAlgorithm", oid!(2.5.29.73))?;
    let value = extension("altSignatureValue", oid!(2.5.29.74))?;

    let signature = match (algorithm, value) {
        (None, None) => None,
        (Some(algorithm), Some(value)) => {
            let set = MlDsa::named(algorithm.value).ok_or_else(|| {
                AuthenticateError::new(
                    "the alternative signature's algorithm is not an ML-DSA this build verifies",
                )
            })?;
            let (0x03, bits, _) = asn1::read(value.value)? else {
                return Err(AuthenticateError::new("altSignatureValue is a BIT STRING"));
            };
            let (&unused, bytes) = bits.split_first().ok_or_else(|| {
                AuthenticateError::new("altSignatureValue is an empty BIT STRING")
            })?;

            if unused != 0 {
                return Err(AuthenticateError::new("altSignatureValue has unused bits"));
            }

            Some((set, bytes.to_vec()))
        }
        _ => {
            return Err(AuthenticateError::new(
                "altSignatureAlgorithm and altSignatureValue come together or not at all",
            ));
        }
    };

    Ok(Alternative {
        public_key,
        signature,
    })
}

fn position(index: usize, length: usize) -> String {
    if index == 0 {
        "the leaf".to_string()
    } else if index + 1 == length {
        "the anchor".to_string()
    } else {
        format!("intermediate {index}")
    }
}

/// Whether a chain's leaf carries an alternative signature at all; what a
/// surface says of a peer before any policy is applied.
///
/// # Errors
///
/// The leaf is not X.509.
pub fn is_hybrid(chain: &Chain) -> Result<bool, AuthenticateError> {
    Ok(carried(chain.leaf())?.signature.is_some())
}

#[cfg(test)]
mod tests {
    use super::super::mint::Authority;
    use super::super::{Anchors, Usage, verify};
    use super::*;

    const NOW: i64 = 1_800_000_000;
    const DAY: i64 = 86_400;

    fn path(root: &Authority, issuer: &Authority) -> (Path, Chain) {
        let issued = issuer.issue("partner-x.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");
        let path = verify(&chain, &anchors, Usage::ClientAuth, None, NOW).expect("classical");
        (path, chain)
    }

    #[test]
    fn a_hybrid_path_verifies_under_every_policy_and_a_legacy_verifier_sees_a_certificate() {
        let root = Authority::hybrid_root("Partner Root");
        let issuing = root.hybrid_intermediate("Partner Issuing CA");
        let (path, chain) = path(&root, &issuing);

        assert!(is_hybrid(&chain).expect("read"));
        assert_eq!(path.certificates().len(), 3);
        verify_alt(&path, Hybrid::Ignored).expect("ignored");
        verify_alt(&path, Hybrid::WherePresent).expect("where present");
        verify_alt(&path, Hybrid::Required).expect("required");
    }

    #[test]
    fn a_classical_path_passes_where_present_and_is_refused_where_required() {
        let root = Authority::root("Partner Root");
        let (path, chain) = path(&root, &root);

        assert!(!is_hybrid(&chain).expect("read"));
        verify_alt(&path, Hybrid::WherePresent).expect("nothing to check");
        let failure = verify_alt(&path, Hybrid::Required).expect_err("required");
        assert!(failure.message.contains("the leaf carries no"), "{failure}");
    }

    #[test]
    fn an_alternative_signature_by_the_wrong_key_is_refused_naming_the_algorithm() {
        let root = Authority::hybrid_root("Partner Root");
        let stranger = Authority::hybrid_root("Somebody Else");
        let issued = root.issue_alt_signed_by(&stranger, "partner-x.example", NOW - DAY, NOW + DAY);
        let chain = Chain::from_pem(&issued.pem).expect("a chain");
        let anchors = Anchors::from_pem(&root.pem()).expect("anchors");
        let path = verify(&chain, &anchors, Usage::ClientAuth, None, NOW).expect("classical");

        let failure = verify_alt(&path, Hybrid::WherePresent).expect_err("forged");
        assert!(failure.message.contains("ML-DSA-65"), "{failure}");
        assert!(failure.message.contains("does not verify"), "{failure}");
    }
}
