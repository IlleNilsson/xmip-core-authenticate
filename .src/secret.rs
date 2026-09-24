//! The hashed secret store with expiry: secrets a node minted with full
//! entropy, kept as their SHA-256 under the name each was issued to, each
//! good until a moment or for ever.
//!
//! `api-key` and `bearer` verify against it (ADR-0050, the candidate of the
//! amendment of 2026-09-19); until 2026-09-24 each carried a store of its
//! own, the same three fields and the same constant-time lookup under two
//! names. What a verifier makes of a name stays with it: an API key is
//! also found by its digest name, which is `api-key`'s.
//!
//! SHA-256 is enough for a secret with full entropy and would not be for a
//! password, which is why the password-shaped verifiers keep theirs in
//! [`crate::store`] instead. A lookup compares the presented hash with every
//! secret it considers, each in constant time and with no early exit.

use crate::clock::Window;
use crate::store::{KEY_LENGTH, constant_time_eq, sha256};

/// One secret as the store holds it.
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct Secret {
    name: String,
    hash: [u8; KEY_LENGTH],
    expiry: Option<i64>,
}

impl Secret {
    /// The name the secret was issued under; never the secret.
    #[must_use]
    pub fn name(&self) -> &str {
        &self.name
    }

    /// SHA-256 of the secret.
    #[must_use]
    pub const fn hash(&self) -> &[u8; KEY_LENGTH] {
        &self.hash
    }

    /// The first second, since the Unix epoch, at which the secret is no
    /// longer good. `None` is a secret that does not expire.
    #[must_use]
    pub const fn expiry(&self) -> Option<i64> {
        self.expiry
    }

    /// When the secret is good, for the clock to admit or refuse.
    #[must_use]
    pub const fn window(&self) -> Window {
        Window::until(self.expiry)
    }
}

/// The secrets a node takes, built from configuration and read-only after.
#[derive(Clone, Debug, Default)]
pub struct SecretStore {
    secrets: Vec<Secret>,
}

impl SecretStore {
    /// A store holding nothing, which verifies nobody.
    #[must_use]
    pub fn new() -> Self {
        Self::default()
    }

    /// Hold `secret` under `name`, hashed. The secret is not kept. A second
    /// secret under the same name stands beside the first, which is how one
    /// is rotated without a gap.
    pub fn insert(&mut self, name: &str, secret: &str, expiry: Option<i64>) {
        self.insert_hash(name, sha256(secret.as_bytes()), expiry);
    }

    /// Hold a secret hashed elsewhere, as configuration carries it.
    pub fn insert_hash(&mut self, name: &str, hash: [u8; KEY_LENGTH], expiry: Option<i64>) {
        self.secrets.push(Secret {
            name: name.to_string(),
            hash,
            expiry,
        });
    }

    /// How many secrets are held.
    #[must_use]
    pub fn len(&self) -> usize {
        self.secrets.len()
    }

    /// Whether nothing is held.
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.secrets.is_empty()
    }

    /// Every secret held, in the order it was inserted.
    pub fn iter(&self) -> impl Iterator<Item = &Secret> {
        self.secrets.iter()
    }

    /// The secret whose hash is `hash`, compared in constant time against
    /// every secret held.
    #[must_use]
    pub fn holding(&self, hash: &[u8; KEY_LENGTH]) -> Option<&Secret> {
        self.holding_where(hash, |_| true)
    }

    /// The secret `considered` accepts whose hash is `hash`, compared in
    /// constant time against every secret it accepts. Finding a secret by
    /// its name proves nothing: a name is public.
    #[must_use]
    pub fn holding_where(
        &self,
        hash: &[u8; KEY_LENGTH],
        considered: impl Fn(&Secret) -> bool,
    ) -> Option<&Secret> {
        self.secrets
            .iter()
            .filter(|secret| considered(secret))
            .fold(None, |found, secret| {
                if constant_time_eq(&secret.hash, hash) {
                    found.or(Some(secret))
                } else {
                    found
                }
            })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_secret_is_found_by_its_hash_and_the_secret_itself_is_not_kept() {
        let mut store = SecretStore::new();
        assert!(store.is_empty());
        store.insert("partner-x", "mF_9.B5f-4.1JqM", Some(42));
        let held = store.holding(&sha256(b"mF_9.B5f-4.1JqM")).expect("held");
        assert_eq!(held.name(), "partner-x");
        assert_eq!(held.expiry(), Some(42));
        assert_eq!(held.window(), Window::until(Some(42)));
        assert_eq!(held.hash(), &sha256(b"mF_9.B5f-4.1JqM"));
        assert_eq!(store.len(), 1);
        assert!(!format!("{store:?}").contains("mF_9.B5f-4.1JqM"));
    }

    #[test]
    fn a_secret_hashed_elsewhere_is_found_and_another_is_not() {
        let mut store = SecretStore::new();
        store.insert_hash("partner-y", sha256(b"opaque"), None);
        assert_eq!(
            store.holding(&sha256(b"opaque")).map(Secret::name),
            Some("partner-y")
        );
        assert!(store.holding(&sha256(b"opaque ")).is_none());
    }

    #[test]
    fn only_what_the_caller_considers_is_compared_and_a_rotation_stands_beside() {
        let mut store = SecretStore::new();
        store.insert("partner-x", "old", Some(100));
        store.insert("partner-x", "new", None);
        store.insert("partner-y", "key-y", None);
        let named = |name: &'static str| move |secret: &Secret| secret.name() == name;

        assert_eq!(
            store
                .iter()
                .filter(|secret| named("partner-x")(secret))
                .count(),
            2
        );
        let expiry = |key: &[u8]| {
            store
                .holding_where(&sha256(key), named("partner-x"))
                .map(Secret::expiry)
        };
        assert_eq!(expiry(b"old"), Some(Some(100)));
        assert_eq!(expiry(b"new"), Some(None));
        assert_eq!(expiry(b"key-y"), None, "another name's secret");
    }
}
