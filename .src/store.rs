//! The credential store the password-shaped verifiers share.
//!
//! ADR-0050 section 6: `password`, `basic`, `digest` and `scram` verify
//! against one store, and the store is the capability's so that none of them
//! depends on another (ADR-0044). One entry per username, and what the entry
//! holds is a SCRAM-SHA-256 verifier as RFC 7677 and PostgreSQL keep it —
//! the salt, the iteration count, the `StoredKey` and the `ServerKey` — and
//! never the password or the salted password. A password is checked by
//! deriving the salted password with PBKDF2-HMAC-SHA256, taking the
//! `ClientKey` from it and comparing `H(ClientKey)` with the `StoredKey` in
//! constant time; a SCRAM exchange is served from the same two keys. Whoever
//! reads the store can therefore verify nobody and impersonate nobody, which
//! is the property RFC 5802 section 9 asks of a server's storage.
//!
//! Digest cannot share the verifier: RFC 7616's `HA1` is a hash of the
//! password itself, per realm and per algorithm, so the store keeps `HA1`
//! beside the verifier for the realms a user was enrolled in — as `htdigest`
//! files do — and computes the SHA-256 one itself.
//!
//! Every hash and derivation here is public because the `scram` verifier
//! needs the same primitives to compute a client signature, and a test needs
//! them to play the client.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::hash::{BuildHasher, RandomState};
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{SystemTime, UNIX_EPOCH};

/// The iteration count a store derives with unless configured otherwise.
/// OWASP's 2023 figure for PBKDF2-HMAC-SHA256; a test uses far fewer.
pub const DEFAULT_ITERATIONS: u32 = 600_000;

/// The width of every key and hash here: SHA-256's.
pub const KEY_LENGTH: usize = 32;

/// The `HA1` algorithm names RFC 7616 spells, as [`CredentialStore::ha1`]
/// takes them.
pub const MD5: &str = "MD5";
pub const SHA_256: &str = "SHA-256";

/// SHA-256 of `data`.
#[must_use]
pub fn sha256(data: &[u8]) -> [u8; KEY_LENGTH] {
    Sha256::digest(data).into()
}

/// HMAC-SHA256 of `data` under `key`.
#[must_use]
pub fn hmac_sha256(key: &[u8], data: &[u8]) -> [u8; KEY_LENGTH] {
    let mut mac = Hmac::<Sha256>::new_from_slice(key).expect("HMAC takes a key of any length");
    mac.update(data);
    mac.finalize().into_bytes().into()
}

/// PBKDF2-HMAC-SHA256 (RFC 8018 section 5.2), one block, which is all a
/// 32-byte key needs. Zero iterations are taken as one.
#[must_use]
pub fn pbkdf2_sha256(password: &[u8], salt: &[u8], iterations: u32) -> [u8; KEY_LENGTH] {
    let mut salted = salt.to_vec();
    salted.extend_from_slice(&1u32.to_be_bytes());
    let mut block = hmac_sha256(password, &salted);
    let mut derived = block;
    for _ in 1..iterations.max(1) {
        block = hmac_sha256(password, &block);
        for (out, next) in derived.iter_mut().zip(block.iter()) {
            *out ^= next;
        }
    }
    derived
}

/// Whether two byte strings are equal, in time that depends on their length
/// and never on where they differ.
#[must_use]
pub fn constant_time_eq(left: &[u8], right: &[u8]) -> bool {
    if left.len() != right.len() {
        return false;
    }
    let difference = left
        .iter()
        .zip(right)
        .fold(0u8, |acc, (a, b)| acc | (a ^ b));
    core::hint::black_box(difference) == 0
}

/// Lower-case hexadecimal, as Digest writes every hash it sends.
#[must_use]
pub fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Sixteen bytes no two enrolments share: the clock, a counter, the name,
/// and a hash keyed at random by the process, all through SHA-256.
#[must_use]
pub fn fresh_salt(username: &str) -> [u8; 16] {
    static ENROLMENTS: AtomicU64 = AtomicU64::new(1);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |since| since.as_nanos());
    let count = ENROLMENTS.fetch_add(1, Ordering::Relaxed);
    let keyed = RandomState::new().hash_one(username);
    let mut seed = Vec::with_capacity(32 + username.len());
    seed.extend_from_slice(&nanos.to_le_bytes());
    seed.extend_from_slice(&count.to_le_bytes());
    seed.extend_from_slice(&keyed.to_le_bytes());
    seed.extend_from_slice(username.as_bytes());
    let mut salt = [0u8; 16];
    salt.copy_from_slice(&sha256(&seed)[..16]);
    salt
}

/// What the store holds for one username: RFC 5802 section 3's four values.
///
/// `StoredKey = H(HMAC(SaltedPassword, "Client Key"))` and
/// `ServerKey = HMAC(SaltedPassword, "Server Key")`, where
/// `SaltedPassword = PBKDF2(password, salt, iterations)`.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Verifier {
    salt: Vec<u8>,
    iterations: u32,
    stored_key: [u8; KEY_LENGTH],
    server_key: [u8; KEY_LENGTH],
}

impl Verifier {
    /// Derive from a password. The password is not kept.
    #[must_use]
    pub fn derive(password: &str, salt: &[u8], iterations: u32) -> Self {
        let salted = pbkdf2_sha256(password.as_bytes(), salt, iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        Self {
            salt: salt.to_vec(),
            iterations,
            stored_key: sha256(&client_key),
            server_key: hmac_sha256(&salted, b"Server Key"),
        }
    }

    /// From the four values as configuration holds them.
    #[must_use]
    pub fn from_keys(
        salt: &[u8],
        iterations: u32,
        stored_key: [u8; KEY_LENGTH],
        server_key: [u8; KEY_LENGTH],
    ) -> Self {
        Self {
            salt: salt.to_vec(),
            iterations,
            stored_key,
            server_key,
        }
    }

    #[must_use]
    pub fn salt(&self) -> &[u8] {
        &self.salt
    }

    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    #[must_use]
    pub const fn stored_key(&self) -> &[u8; KEY_LENGTH] {
        &self.stored_key
    }

    #[must_use]
    pub const fn server_key(&self) -> &[u8; KEY_LENGTH] {
        &self.server_key
    }

    /// Whether `password` is the one this was derived from, in constant time
    /// once the derivation is done.
    #[must_use]
    pub fn matches(&self, password: &str) -> bool {
        let salted = pbkdf2_sha256(password.as_bytes(), &self.salt, self.iterations);
        let client_key = hmac_sha256(&salted, b"Client Key");
        constant_time_eq(&sha256(&client_key), &self.stored_key)
    }

    /// Whether `client_key` — recovered from a SCRAM `ClientProof` — is the
    /// one behind the `StoredKey`.
    #[must_use]
    pub fn proves(&self, client_key: &[u8]) -> bool {
        constant_time_eq(&sha256(client_key), &self.stored_key)
    }
}

/// Salted verifiers keyed by username, and `HA1` per realm for Digest.
///
/// Built from configuration through [`CredentialStore::from_entries`] or
/// [`CredentialStore::insert_verifier`]; the first derives, the second takes
/// what was derived elsewhere. A store is read-only once built and can be
/// shared between threads.
#[derive(Debug)]
pub struct CredentialStore {
    iterations: u32,
    verifiers: HashMap<String, Verifier>,
    ha1: HashMap<(String, String, String), String>,
    /// Verified against when the username is unknown, so that an unknown
    /// name costs the same time as a wrong password.
    decoy: Verifier,
}

impl Default for CredentialStore {
    fn default() -> Self {
        Self::new()
    }
}

impl CredentialStore {
    /// An empty store deriving with [`DEFAULT_ITERATIONS`].
    #[must_use]
    pub fn new() -> Self {
        Self::with_iterations(DEFAULT_ITERATIONS)
    }

    /// An empty store deriving with `iterations`.
    #[must_use]
    pub fn with_iterations(iterations: u32) -> Self {
        Self {
            iterations,
            verifiers: HashMap::new(),
            ha1: HashMap::new(),
            decoy: Verifier::derive("", &fresh_salt(""), iterations),
        }
    }

    /// A store enrolling every `(username, password)` given, deriving with
    /// `iterations`.
    #[must_use]
    pub fn from_entries<'a>(
        iterations: u32,
        entries: impl IntoIterator<Item = (&'a str, &'a str)>,
    ) -> Self {
        let mut store = Self::with_iterations(iterations);
        for (username, password) in entries {
            store.insert(username, password);
        }
        store
    }

    /// The iteration count new enrolments derive with.
    #[must_use]
    pub const fn iterations(&self) -> u32 {
        self.iterations
    }

    /// Enrol a password under a fresh salt. A second enrolment of the same
    /// name replaces the first.
    pub fn insert(&mut self, username: &str, password: &str) {
        let salt = fresh_salt(username);
        self.insert_verifier(username, Verifier::derive(password, &salt, self.iterations));
    }

    /// Enrol a verifier derived elsewhere.
    pub fn insert_verifier(&mut self, username: &str, verifier: Verifier) {
        self.verifiers.insert(username.to_string(), verifier);
    }

    /// The verifier enrolled under `username`, for a SCRAM exchange.
    #[must_use]
    pub fn verifier(&self, username: &str) -> Option<&Verifier> {
        self.verifiers.get(username)
    }

    /// Whether `username` is enrolled.
    #[must_use]
    pub fn contains(&self, username: &str) -> bool {
        self.verifiers.contains_key(username)
    }

    /// The usernames enrolled, in no order.
    pub fn usernames(&self) -> impl Iterator<Item = &str> {
        self.verifiers.keys().map(String::as_str)
    }

    /// Whether `password` is the one enrolled under `username`.
    ///
    /// Takes the same time for an unknown name as for a wrong password, so
    /// the store does not say which names it knows.
    #[must_use]
    pub fn verify(&self, username: &str, password: &str) -> bool {
        match self.verifiers.get(username) {
            Some(verifier) => verifier.matches(password),
            None => {
                let _ = self.decoy.matches(password);
                false
            }
        }
    }

    /// Keep an `HA1` an operator computed elsewhere — an `htdigest` line —
    /// as lower-case hexadecimal, for `realm` and `algorithm` ([`MD5`] or
    /// [`SHA_256`]).
    pub fn insert_ha1(&mut self, username: &str, realm: &str, algorithm: &str, ha1: &str) {
        self.ha1.insert(
            (
                username.to_string(),
                realm.to_string(),
                algorithm.to_string(),
            ),
            ha1.to_ascii_lowercase(),
        );
    }

    /// Compute and keep the SHA-256 `HA1` for `realm`:
    /// `SHA-256(username:realm:password)`. The MD5 one is the `digest`
    /// verifier's to compute, since MD5 is not this capability's dependency.
    pub fn insert_sha256_ha1(&mut self, username: &str, realm: &str, password: &str) {
        let ha1 = hex(&sha256(format!("{username}:{realm}:{password}").as_bytes()));
        self.insert_ha1(username, realm, SHA_256, &ha1);
    }

    /// The `HA1` kept for `username` in `realm` under `algorithm`.
    #[must_use]
    pub fn ha1(&self, username: &str, realm: &str, algorithm: &str) -> Option<&str> {
        self.ha1
            .get(&(
                username.to_string(),
                realm.to_string(),
                algorithm.to_string(),
            ))
            .map(String::as_str)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const ITERATIONS: u32 = 4096;

    #[test]
    fn the_derivation_is_pbkdf2_hmac_sha256_by_the_published_vector() {
        // The widely reproduced vector for ("password", "salt", 4096).
        let derived = pbkdf2_sha256(b"password", b"salt", 4096);
        assert_eq!(
            hex(&derived),
            "c5e478d59288c841aa530db6845c4c8d962893a001ce4e11a4963873aa98134a"
        );
        assert_eq!(
            hex(&pbkdf2_sha256(b"password", b"salt", 1)),
            "120fb6cffcf8b32c43e7225256c4f837a86548c92ccc35480805987cb70be17b"
        );
    }

    #[test]
    fn the_right_password_verifies_and_a_wrong_one_does_not() {
        let store = CredentialStore::from_entries(ITERATIONS, [("alice", "pencil")]);
        assert!(store.verify("alice", "pencil"));
        assert!(!store.verify("alice", "pencil "));
        assert!(!store.verify("alice", ""));
    }

    #[test]
    fn an_unknown_name_is_refused_without_saying_it_is_unknown() {
        let store = CredentialStore::from_entries(ITERATIONS, [("alice", "pencil")]);
        assert!(!store.verify("bob", "pencil"));
        assert!(!store.contains("bob"));
        assert_eq!(store.usernames().collect::<Vec<_>>(), ["alice"]);
    }

    #[test]
    fn the_password_and_the_salted_password_are_not_kept() {
        let mut store = CredentialStore::with_iterations(ITERATIONS);
        store.insert("alice", "pencil");
        let verifier = store.verifier("alice").expect("enrolled");
        let printed = format!("{verifier:?}");
        assert!(!printed.contains("pencil"));
        let salted = pbkdf2_sha256(b"pencil", verifier.salt(), ITERATIONS);
        assert_ne!(verifier.stored_key(), &salted);
        assert_ne!(verifier.server_key(), &salted);
        // What is kept is what RFC 5802 says: H(ClientKey) and ServerKey.
        assert_eq!(
            verifier.stored_key(),
            &sha256(&hmac_sha256(&salted, b"Client Key"))
        );
        assert_eq!(verifier.server_key(), &hmac_sha256(&salted, b"Server Key"));
    }

    #[test]
    fn two_enrolments_of_one_password_take_two_salts() {
        let mut store = CredentialStore::with_iterations(ITERATIONS);
        store.insert("alice", "pencil");
        store.insert("carol", "pencil");
        let alice = store.verifier("alice").expect("enrolled");
        let carol = store.verifier("carol").expect("enrolled");
        assert_ne!(alice.salt(), carol.salt());
        assert_ne!(alice.stored_key(), carol.stored_key());
    }

    #[test]
    fn a_verifier_from_configuration_verifies_as_a_derived_one_does() {
        let derived = Verifier::derive("pencil", b"0123456789abcdef", ITERATIONS);
        let configured = Verifier::from_keys(
            b"0123456789abcdef",
            ITERATIONS,
            *derived.stored_key(),
            *derived.server_key(),
        );
        let mut store = CredentialStore::with_iterations(ITERATIONS);
        store.insert_verifier("alice", configured);
        assert!(store.verify("alice", "pencil"));
        assert!(!store.verify("alice", "pen"));
    }

    #[test]
    fn a_client_key_proves_the_stored_key_it_hashes_to() {
        let verifier = Verifier::derive("pencil", b"salt", ITERATIONS);
        let salted = pbkdf2_sha256(b"pencil", b"salt", ITERATIONS);
        assert!(verifier.proves(&hmac_sha256(&salted, b"Client Key")));
        assert!(!verifier.proves(&hmac_sha256(&salted, b"Server Key")));
    }

    #[test]
    fn ha1_is_kept_per_realm_and_per_algorithm() {
        let mut store = CredentialStore::with_iterations(ITERATIONS);
        store.insert_sha256_ha1("alice", "xmip", "pencil");
        store.insert_ha1("alice", "xmip", MD5, "0A1B2C");
        assert_eq!(
            store.ha1("alice", "xmip", SHA_256),
            Some(hex(&sha256(b"alice:xmip:pencil")).as_str())
        );
        assert_eq!(store.ha1("alice", "xmip", MD5), Some("0a1b2c"));
        assert_eq!(store.ha1("alice", "other", SHA_256), None);
        assert_eq!(store.ha1("bob", "xmip", SHA_256), None);
    }

    #[test]
    fn a_constant_time_compare_is_still_a_compare() {
        assert!(constant_time_eq(b"abc", b"abc"));
        assert!(!constant_time_eq(b"abc", b"abd"));
        assert!(!constant_time_eq(b"abc", b"ab"));
        assert!(constant_time_eq(b"", b""));
    }
}
