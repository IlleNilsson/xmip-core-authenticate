//! What has been presented once and may not be presented again.
//!
//! A signed assertion and a Kerberos authenticator each prove something
//! once, and a copy of either proves it again to a verifier that does not
//! remember: SAML Core 2.5.1.5 has a relying party keep the assertion's ID
//! until it expires, RFC 4120 section 3.2.3 has a server keep each
//! authenticator it accepts until its clock skew has passed. The memory is
//! here, once, and both call it.
//!
//! A key is kept until the second it stops mattering and then forgotten.
//! The cache holds at most its capacity, and a cache full of keys that
//! still matter refuses the next key rather than forget one: a forgotten
//! key could be replayed.

use std::collections::HashMap;
use std::sync::Mutex;

use xcore::lock::Locked;

use crate::AuthenticateError;

/// How many keys a cache holds unless told otherwise.
pub const CAPACITY: usize = 65_536;

/// The keys presented, each with the second after which it is forgotten.
#[derive(Debug)]
pub struct Replay {
    seen: Mutex<HashMap<String, i64>>,
    capacity: usize,
}

impl Default for Replay {
    fn default() -> Self {
        Self::holding(CAPACITY)
    }
}

impl Replay {
    /// A cache of at most `capacity` keys.
    #[must_use]
    pub fn holding(capacity: usize) -> Self {
        Self {
            seen: Mutex::new(HashMap::new()),
            capacity,
        }
    }

    /// Spend `key`, remembered until `until`, at `now`.
    ///
    /// # Errors
    ///
    /// Where `key` was spent before and is still remembered — a replay —
    /// and where the cache is full of keys that still matter.
    pub fn spend(&self, key: &str, until: i64, now: i64) -> Result<(), AuthenticateError> {
        let mut seen = self.seen.locked();
        if seen.get(key).is_some_and(|kept| *kept >= now) {
            return Err(AuthenticateError::new(
                "it was presented before and is refused as a replay",
            ));
        }
        if seen.len() >= self.capacity {
            seen.retain(|_, kept| *kept >= now);
        }
        if seen.len() >= self.capacity {
            return Err(AuthenticateError::new(format!(
                "the replay cache holds {} credentials that have not expired, and forgetting \
                 one would let it be replayed",
                seen.len()
            )));
        }
        seen.insert(key.to_string(), until);
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_key_spends_once_until_it_is_forgotten() {
        let cache = Replay::default();

        cache.spend("_a1", 100, 10).expect("the first time");
        let replay = cache.spend("_a1", 100, 50).expect_err("a replay");
        assert!(replay.message.contains("replay"), "{replay}");
        cache.spend("_a1", 200, 101).expect("forgotten after 100");
    }

    #[test]
    fn a_full_cache_forgets_what_expired_and_refuses_rather_than_forget_the_rest() {
        let cache = Replay::holding(2);
        cache.spend("old", 10, 0).expect("spent");
        cache.spend("live", 100, 0).expect("spent");

        cache.spend("new", 100, 50).expect("old has expired");
        let full = cache.spend("more", 100, 50).expect_err("full");
        assert!(full.message.contains("have not expired"), "{full}");
    }
}
