//! The two-pass signing a hybrid certificate takes: the alternative
//! signature covers the certificate without its own extension and without
//! the classical `signature` field, so the certificate is signed once to
//! learn those bytes, alternative-signed, then signed again with the
//! alternative signature in place. The classical signature covers all three
//! extensions, as ITU-T X.509 (10/2019) clause 7.2.2 says.

use crate::x509::der;
use aws_lc_rs::encoding::{AsDer, PublicKeyX509Der};
use aws_lc_rs::signature::{KeyPair as _, PqdsaKeyPair};
use rcgen::{Certificate, CertificateParams, CustomExtension, KeyPair};
use rustls_pki_types::alg_id;

const SUBJECT_ALT_PUBLIC_KEY_INFO: &[u64] = &[2, 5, 29, 72];
const ALT_SIGNATURE_ALGORITHM: &[u64] = &[2, 5, 29, 73];
const ALT_SIGNATURE_VALUE: &[u64] = &[2, 5, 29, 74];

pub(super) fn sign(
    mut params: CertificateParams,
    key: &KeyPair,
    own_alt: &PqdsaKeyPair,
    alt_signer: &PqdsaKeyPair,
    classical: &dyn Fn(CertificateParams, &KeyPair) -> Certificate,
) -> Certificate {
    let public: PublicKeyX509Der<'_> = own_alt.public_key().as_der().expect("an SPKI");
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            SUBJECT_ALT_PUBLIC_KEY_INFO,
            public.as_ref().to_vec(),
        ));
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            ALT_SIGNATURE_ALGORITHM,
            asn1::tlv(0x30, alg_id::ML_DSA_65.as_ref()),
        ));

    let draft = classical(params.clone(), key);
    let signed = der::pre_tbs(draft.der()).expect("a pre-TBS");
    let mut signature = vec![0u8; 8_192];
    let length = alt_signer
        .sign(&signed, &mut signature)
        .expect("an ML-DSA signature");
    signature.truncate(length);

    let mut bits = vec![0u8];
    bits.extend(signature);
    params
        .custom_extensions
        .push(CustomExtension::from_oid_content(
            ALT_SIGNATURE_VALUE,
            asn1::tlv(0x03, &bits),
        ));

    classical(params, key)
}
