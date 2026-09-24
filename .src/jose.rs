//! The keys a JWS is verified with (RFC 7515, 7517, 7518), for the two
//! technologies that verify one: `jwt` and `oidc`.
//!
//! RFC 7518 makes HS256 required and RS256 and ES256 recommended, and those
//! three are what is checked. A key serves one algorithm: a shared secret
//! HS256, an RSA public key RS256, a P-256 public key ES256. A key may carry
//! the `kid` a token names it by. Until 2026-09-24 each technology held its
//! own key type, and the two chose a key differently: one tried only the
//! first key of the algorithm where a token named none, the other every one.
//! The rule is [`KeySet::verify`]'s now.
//!
//! A set is configuration, never fetched (ADR-0045): keys handed over one by
//! one, or a JSON Web Key Set document ([`KeySet::from_jwks`]) as an issuer
//! publishes it. Off unless a technology turns the `jose` feature on.

use crate::AuthenticateError;
use hmac::{Hmac, Mac};
use rsa::pkcs8::DecodePublicKey;
use rsa::signature::Verifier as _;
use serde_json::Value;
use sha2::Sha256;
use std::fmt;

/// One of the three signature algorithms verified here.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Algorithm {
    /// HMAC over SHA-256 with a shared secret.
    Hs256,
    /// RSASSA-PKCS1-v1_5 over SHA-256.
    Rs256,
    /// ECDSA on P-256 over SHA-256.
    Es256,
}

impl Algorithm {
    /// The algorithm an `alg` header names, where it is one of the three.
    /// Compared exactly: `hs256` and `none` are not.
    #[must_use]
    pub fn named(name: &str) -> Option<Self> {
        match name {
            "HS256" => Some(Self::Hs256),
            "RS256" => Some(Self::Rs256),
            "ES256" => Some(Self::Es256),
            _ => None,
        }
    }

    /// The `alg` name.
    #[must_use]
    pub const fn name(self) -> &'static str {
        match self {
            Self::Hs256 => "HS256",
            Self::Rs256 => "RS256",
            Self::Es256 => "ES256",
        }
    }
}

/// What a key is made of.
#[derive(Clone)]
enum Material {
    Secret(Vec<u8>),
    Rsa(rsa::RsaPublicKey),
    P256(p256::ecdsa::VerifyingKey),
}

/// A key the node holds, serving one algorithm.
#[derive(Clone)]
pub struct Key {
    id: Option<String>,
    material: Material,
}

// The material is a secret or a public key of many bytes; neither belongs in
// a log line. The id and the algorithm say which key this is.
#[allow(clippy::missing_fields_in_debug)]
impl fmt::Debug for Key {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Key")
            .field("id", &self.id)
            .field("algorithm", &self.algorithm().name())
            .finish()
    }
}

impl Key {
    /// A shared secret, for HS256.
    #[must_use]
    pub fn secret(id: Option<&str>, secret: impl AsRef<[u8]>) -> Self {
        Self::of(id, Material::Secret(secret.as_ref().to_vec()))
    }

    /// An RSA public key from its SPKI PEM (`-----BEGIN PUBLIC KEY-----`),
    /// for RS256.
    ///
    /// # Errors
    ///
    /// Where the text is not an RSA public key in PEM.
    pub fn rsa_pem(id: Option<&str>, pem: &str) -> Result<Self, AuthenticateError> {
        let key = rsa::RsaPublicKey::from_public_key_pem(pem)
            .map_err(|_| AuthenticateError::new("the RSA key is not a public key in PEM"))?;
        Ok(Self::of(id, Material::Rsa(key)))
    }

    /// An RSA public key from its big-endian modulus and exponent, as a JWK
    /// carries them, for RS256.
    ///
    /// # Errors
    ///
    /// Where the pair is not a usable RSA key.
    pub fn rsa_components(
        id: Option<&str>,
        modulus: &[u8],
        exponent: &[u8],
    ) -> Result<Self, AuthenticateError> {
        let key = rsa::RsaPublicKey::new(
            rsa::BigUint::from_bytes_be(modulus),
            rsa::BigUint::from_bytes_be(exponent),
        )
        .map_err(|_| AuthenticateError::new("the RSA modulus and exponent are not a key"))?;
        Ok(Self::of(id, Material::Rsa(key)))
    }

    /// A P-256 public key from its SPKI PEM, for ES256.
    ///
    /// # Errors
    ///
    /// Where the text is not a P-256 public key in PEM.
    pub fn p256_pem(id: Option<&str>, pem: &str) -> Result<Self, AuthenticateError> {
        let key = p256::PublicKey::from_public_key_pem(pem)
            .map_err(|_| AuthenticateError::new("the P-256 key is not a public key in PEM"))?;
        Ok(Self::of(
            id,
            Material::P256(p256::ecdsa::VerifyingKey::from(&key)),
        ))
    }

    /// A P-256 public key from its affine coordinates, as a JWK carries
    /// them, for ES256.
    ///
    /// # Errors
    ///
    /// Where the coordinates are not thirty-two bytes each or not a point on
    /// the curve.
    pub fn p256_point(id: Option<&str>, x: &[u8], y: &[u8]) -> Result<Self, AuthenticateError> {
        if x.len() != 32 || y.len() != 32 {
            return Err(AuthenticateError::new(
                "a P-256 coordinate is thirty-two bytes",
            ));
        }
        let point = p256::EncodedPoint::from_affine_coordinates(x.into(), y.into(), false);
        let key = p256::ecdsa::VerifyingKey::from_encoded_point(&point)
            .map_err(|_| AuthenticateError::new("the P-256 coordinates are not on the curve"))?;
        Ok(Self::of(id, Material::P256(key)))
    }

    fn of(id: Option<&str>, material: Material) -> Self {
        Self {
            id: id.map(str::to_string),
            material,
        }
    }

    /// The `kid` this key answers to, where it has one.
    #[must_use]
    pub fn id(&self) -> Option<&str> {
        self.id.as_deref()
    }

    /// The one algorithm this key serves.
    #[must_use]
    pub const fn algorithm(&self) -> Algorithm {
        match self.material {
            Material::Secret(_) => Algorithm::Hs256,
            Material::Rsa(_) => Algorithm::Rs256,
            Material::P256(_) => Algorithm::Es256,
        }
    }

    /// Whether `signature` is this key's over `input`.
    fn holds(&self, input: &[u8], signature: &[u8]) -> bool {
        match &self.material {
            Material::Secret(secret) => {
                Hmac::<Sha256>::new_from_slice(secret).is_ok_and(|mut mac| {
                    mac.update(input);
                    mac.verify_slice(signature).is_ok()
                })
            }
            Material::Rsa(key) => {
                let key = rsa::pkcs1v15::VerifyingKey::<Sha256>::new(key.clone());
                rsa::pkcs1v15::Signature::try_from(signature)
                    .is_ok_and(|signature| key.verify(input, &signature).is_ok())
            }
            Material::P256(key) => p256::ecdsa::Signature::from_slice(signature)
                .is_ok_and(|signature| key.verify(input, &signature).is_ok()),
        }
    }
}

/// The keys a node verifies tokens with.
#[derive(Clone, Debug)]
pub struct KeySet {
    keys: Vec<Key>,
}

impl KeySet {
    /// These keys.
    #[must_use]
    pub const fn new(keys: Vec<Key>) -> Self {
        Self { keys }
    }

    /// Read a JSON Web Key Set document: RSA keys (`kty` `RSA`, `n` and `e`)
    /// for RS256 and P-256 keys (`kty` `EC`, `crv` `P-256`, `x` and `y`) for
    /// ES256. A key marked `"use":"enc"` is not a signing key and is passed
    /// over, as is a key of any other type.
    ///
    /// # Errors
    ///
    /// Where the text is not JSON with a `keys` array, a key of a type read
    /// here is malformed, or no key in the set is one that can be used, so a
    /// useless set is refused when it is loaded, not at the first token.
    pub fn from_jwks(document: &str) -> Result<Self, AuthenticateError> {
        let value: Value = serde_json::from_str(document).map_err(|failure| {
            AuthenticateError::new(format!("the JWKS is not JSON: {failure}"))
        })?;
        let listed = value
            .get("keys")
            .and_then(Value::as_array)
            .ok_or_else(|| AuthenticateError::new("the JWKS has no `keys` array"))?;

        let mut keys = Vec::new();
        for entry in listed {
            if entry.get("use").and_then(Value::as_str) == Some("enc") {
                continue;
            }
            let id = entry.get("kid").and_then(Value::as_str);
            match entry.get("kty").and_then(Value::as_str) {
                Some("RSA") => keys.push(
                    Key::rsa_components(id, &member(entry, "n")?, &member(entry, "e")?).map_err(
                        |_| AuthenticateError::new("an RSA key in the JWKS is not a usable key"),
                    )?,
                ),
                Some("EC") if entry.get("crv").and_then(Value::as_str) == Some("P-256") => {
                    keys.push(Key::p256_point(
                        id,
                        &member(entry, "x")?,
                        &member(entry, "y")?,
                    )?);
                }
                _ => {}
            }
        }

        if keys.is_empty() {
            return Err(AuthenticateError::new(
                "the JWKS holds no RSA or P-256 signing key",
            ));
        }
        Ok(Self { keys })
    }

    /// How many keys the set holds.
    #[must_use]
    pub fn len(&self) -> usize {
        self.keys.len()
    }

    /// Whether it holds none.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.keys.is_empty()
    }

    /// Check `signature` over `input`: with the key the token names, which
    /// must serve `algorithm`, or, where it names none, with every key of
    /// the algorithm until one holds.
    ///
    /// # Errors
    ///
    /// Where the set holds no such key, the named key serves another
    /// algorithm, or the signature does not verify.
    pub fn verify(
        &self,
        algorithm: Algorithm,
        key_id: Option<&str>,
        input: &[u8],
        signature: &[u8],
    ) -> Result<(), AuthenticateError> {
        let candidates: Vec<&Key> = match key_id {
            Some(id) => {
                let key = self
                    .keys
                    .iter()
                    .find(|key| key.id() == Some(id))
                    .ok_or_else(|| {
                        AuthenticateError::new(format!(
                            "the node holds no key '{id}': its issuer may have rotated its keys"
                        ))
                    })?;
                if key.algorithm() != algorithm {
                    return Err(AuthenticateError::new(format!(
                        "the key '{id}' serves {} and the token is signed {}",
                        key.algorithm().name(),
                        algorithm.name()
                    )));
                }
                vec![key]
            }
            None => self
                .keys
                .iter()
                .filter(|key| key.algorithm() == algorithm)
                .collect(),
        };
        if candidates.is_empty() {
            return Err(AuthenticateError::new(format!(
                "the node holds no {} key and the token names none",
                algorithm.name()
            )));
        }

        if candidates.iter().any(|key| key.holds(input, signature)) {
            Ok(())
        } else {
            Err(AuthenticateError::new(format!(
                "the {} signature does not verify with the keys the node holds",
                algorithm.name()
            )))
        }
    }
}

/// One base64url member of a key, decoded by the identify capability's
/// reader, the one the compact token is read with.
fn member(entry: &Value, name: &str) -> Result<Vec<u8>, AuthenticateError> {
    let text = entry
        .get(name)
        .and_then(Value::as_str)
        .ok_or_else(|| AuthenticateError::new(format!("a key in the JWKS has no `{name}`")))?;
    identify::jwt::decode(text, name).map_err(|_| {
        AuthenticateError::new(format!("a key's `{name}` in the JWKS is not base64url"))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use p256::ecdsa::signature::Signer;

    fn signing_key() -> p256::ecdsa::SigningKey {
        p256::ecdsa::SigningKey::random(&mut rand::rngs::OsRng)
    }

    /// A P-256 key as a JWK, as an issuer would publish it.
    fn p256_jwk(id: &str, key: &p256::ecdsa::SigningKey) -> String {
        let point = key.verifying_key().to_encoded_point(false);
        format!(
            r#"{{"kty":"EC","crv":"P-256","use":"sig","kid":"{id}","x":"{}","y":"{}"}}"#,
            codec::base64::encode_url_unpadded(point.x().expect("x")),
            codec::base64::encode_url_unpadded(point.y().expect("y"))
        )
    }

    fn published(key: &p256::ecdsa::SigningKey) -> KeySet {
        KeySet::from_jwks(&format!(r#"{{"keys":[{}]}}"#, p256_jwk("e1", key))).expect("set")
    }

    #[test]
    fn an_algorithm_is_named_by_its_header_value_and_nothing_else() {
        assert_eq!(Algorithm::named("HS256"), Some(Algorithm::Hs256));
        assert_eq!(Algorithm::named("none"), None);
        assert_eq!(Algorithm::named("hs256"), None);
    }

    #[test]
    fn a_published_p256_key_verifies_what_its_private_half_signed() {
        let key = signing_key();
        let set = published(&key);
        let signature: p256::ecdsa::Signature = key.sign(b"input");
        let signature = signature.to_vec();

        assert_eq!(set.len(), 1);
        assert!(
            set.verify(Algorithm::Es256, Some("e1"), b"input", &signature)
                .is_ok()
        );
        assert!(
            set.verify(Algorithm::Es256, None, b"input", &signature)
                .is_ok()
        );
        let failure = set
            .verify(Algorithm::Es256, Some("e1"), b"other", &signature)
            .expect_err("refused");
        assert!(failure.message.contains("does not verify"));
    }

    #[test]
    fn with_no_kid_every_key_of_the_algorithm_is_tried_not_the_first() {
        let first = signing_key();
        let second = signing_key();
        let set = KeySet::from_jwks(&format!(
            r#"{{"keys":[{},{}]}}"#,
            p256_jwk("a", &first),
            p256_jwk("b", &second)
        ))
        .expect("set");
        let signature: p256::ecdsa::Signature = second.sign(b"input");

        assert!(
            set.verify(Algorithm::Es256, None, b"input", &signature.to_vec())
                .is_ok()
        );
    }

    #[test]
    fn a_missing_or_mismatched_key_is_refused_by_name() {
        let set = published(&signing_key());

        let missing = set
            .verify(Algorithm::Es256, Some("e2"), b"input", b"sig")
            .expect_err("refused");
        let mismatched = set
            .verify(Algorithm::Rs256, Some("e1"), b"input", b"sig")
            .expect_err("refused");
        let none = set
            .verify(Algorithm::Hs256, None, b"input", b"sig")
            .expect_err("refused");

        assert!(missing.message.contains("no key 'e2'"));
        assert!(missing.message.contains("rotated"));
        assert!(mismatched.message.contains("serves ES256"));
        assert!(none.message.contains("no HS256 key"));
    }

    #[test]
    fn a_secret_serves_hs256_and_prints_its_id_and_never_its_bytes() {
        let key = Key::secret(Some("k1"), b"hidden");
        let mut mac = Hmac::<Sha256>::new_from_slice(b"hidden").expect("a key");
        mac.update(b"input");
        let signature = mac.finalize().into_bytes();
        let set = KeySet::new(vec![key.clone()]);

        assert_eq!(key.algorithm(), Algorithm::Hs256);
        assert!(
            set.verify(Algorithm::Hs256, Some("k1"), b"input", &signature)
                .is_ok()
        );
        let printed = format!("{key:?}");
        assert!(printed.contains("k1") && !printed.contains("hidden"));
    }

    #[test]
    fn a_set_with_nothing_usable_or_no_keys_array_does_not_load() {
        let unusable = r#"{"keys":[{"kty":"oct","k":"AA"},{"kty":"RSA","use":"enc"}]}"#;
        let failure = KeySet::from_jwks(unusable).expect_err("refused");
        assert!(failure.message.contains("no RSA or P-256 signing key"));

        let failure = KeySet::from_jwks(r#"{"issuer":"x"}"#).expect_err("refused");
        assert!(failure.message.contains("`keys`"));

        let short = Key::p256_point(None, &[1; 31], &[2; 32]).expect_err("refused");
        assert!(short.message.contains("thirty-two"));
    }
}
