//! The time a verifier reads, how far it forgives another clock, and the
//! window a credential is valid in.
//!
//! A token's `nbf` and `exp`, an assertion's `NotBefore` and
//! `NotOnOrAfter`, a ticket's `starttime` and `endtime`, a stored key's
//! expiry: each is a window, and each verifier held it against a clock of
//! its own until 2026-09-24 — ten copies of the same `now()`, and four
//! readings of the same bound, one of which let a token through for a
//! second after its `exp`. The rule is here and every verifier calls it.
//!
//! A window is `[not_before, not_on_or_after)`: RFC 7519 section 4.1.4 has a
//! token refused *on or after* its `exp` and section 4.1.5 *before* its
//! `nbf`, and SAML Core 2.5.1.2 says the same of `NotBefore` and
//! `NotOnOrAfter`. A mechanism whose last valid second is inclusive, as a
//! Kerberos `endtime` is, passes the second after it. The leeway widens the
//! window at both ends: how far another clock may be off from this one.

use std::fmt;
use std::time::SystemTime;

/// Where the time comes from and how far another clock may be off.
pub struct Clock {
    read: Box<dyn Fn() -> i64 + Send + Sync>,
    leeway: i64,
}

impl Clock {
    /// The system clock, forgiving `leeway` seconds.
    #[must_use]
    pub fn system(leeway: i64) -> Self {
        Self {
            read: Box::new(now),
            leeway,
        }
    }

    /// The same leeway, the time read from `read` instead: a test pins it.
    #[must_use]
    pub fn reading(self, read: impl Fn() -> i64 + Send + Sync + 'static) -> Self {
        Self {
            read: Box::new(read),
            leeway: self.leeway,
        }
    }

    /// The same source, forgiving `seconds` instead.
    #[must_use]
    pub fn forgiving(self, seconds: i64) -> Self {
        Self {
            read: self.read,
            leeway: seconds,
        }
    }

    /// Seconds since the Unix epoch, now.
    #[must_use]
    pub fn now(&self) -> i64 {
        (self.read)()
    }

    /// How far another clock may be off, in seconds.
    #[must_use]
    pub const fn leeway(&self) -> i64 {
        self.leeway
    }

    /// Whether now lies inside `window`, widened by the leeway at both ends.
    ///
    /// # Errors
    ///
    /// Which end it lies outside, and when it is.
    pub fn admits(&self, window: Window) -> Result<(), Outside> {
        let now = self.now();
        if let Some(not_before) = window.not_before
            && now.saturating_add(self.leeway) < not_before
        {
            return Err(Outside::Early { not_before, now });
        }
        if let Some(not_on_or_after) = window.not_on_or_after
            && now.saturating_sub(self.leeway) >= not_on_or_after
        {
            return Err(Outside::Late {
                not_on_or_after,
                now,
            });
        }
        Ok(())
    }
}

impl fmt::Debug for Clock {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Clock")
            .field("now", &self.now())
            .field("leeway", &self.leeway)
            .finish()
    }
}

/// Seconds since the Unix epoch, now, by the system clock.
#[must_use]
pub fn now() -> i64 {
    codec::civil::unix_seconds(SystemTime::now())
}

/// When a credential is valid: from `not_before`, until `not_on_or_after`.
/// Either end may be open.
#[derive(Clone, Copy, Debug, Default, Eq, PartialEq)]
pub struct Window {
    /// The first second it is valid.
    pub not_before: Option<i64>,
    /// The first second it is no longer valid.
    pub not_on_or_after: Option<i64>,
}

impl Window {
    /// Valid from `not_before` until `not_on_or_after`, either open.
    #[must_use]
    pub const fn between(not_before: Option<i64>, not_on_or_after: Option<i64>) -> Self {
        Self {
            not_before,
            not_on_or_after,
        }
    }

    /// Valid until `not_on_or_after`, from whenever.
    #[must_use]
    pub const fn until(not_on_or_after: Option<i64>) -> Self {
        Self::between(None, not_on_or_after)
    }
}

/// Which end of its window a credential was presented outside.
#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum Outside {
    /// Before it became valid.
    Early { not_before: i64, now: i64 },
    /// On or after it stopped being valid.
    Late { not_on_or_after: i64, now: i64 },
}

/// The words a refusal takes after naming what was refused: *the token*
/// `is not valid before 1800000000 and it is 1799990000`.
impl fmt::Display for Outside {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Early { not_before, now } => {
                write!(f, "is not valid before {not_before} and it is {now}")
            }
            Self::Late {
                not_on_or_after,
                now,
            } => write!(f, "expired at {not_on_or_after} and it is {now}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_800_000_000;

    fn clock(leeway: i64) -> Clock {
        Clock::system(leeway).reading(|| NOW)
    }

    #[test]
    fn a_window_holds_its_first_second_and_not_its_last() {
        let window = Window::between(Some(NOW), Some(NOW + 1));
        assert_eq!(clock(0).admits(window), Ok(()));
        assert_eq!(
            clock(0).admits(Window::until(Some(NOW))),
            Err(Outside::Late {
                not_on_or_after: NOW,
                now: NOW
            })
        );
        assert_eq!(
            clock(0).admits(Window::between(Some(NOW + 1), None)),
            Err(Outside::Early {
                not_before: NOW + 1,
                now: NOW
            })
        );
        assert_eq!(clock(0).admits(Window::default()), Ok(()));
    }

    #[test]
    fn the_leeway_widens_both_ends_and_no_further() {
        let clock = clock(60);
        assert_eq!(clock.admits(Window::until(Some(NOW - 59))), Ok(()));
        assert!(clock.admits(Window::until(Some(NOW - 60))).is_err());
        assert_eq!(clock.admits(Window::between(Some(NOW + 60), None)), Ok(()));
        assert!(clock.admits(Window::between(Some(NOW + 61), None)).is_err());
    }

    #[test]
    fn a_refusal_says_which_end_and_when() {
        let early = Outside::Early {
            not_before: 5,
            now: 3,
        };
        let late = Outside::Late {
            not_on_or_after: 5,
            now: 7,
        };
        assert_eq!(early.to_string(), "is not valid before 5 and it is 3");
        assert_eq!(late.to_string(), "expired at 5 and it is 7");
    }

    #[test]
    fn the_system_clock_is_after_this_was_written_and_forgiving_keeps_the_source() {
        assert!(now() > 1_790_000_000);
        let pinned = clock(0).forgiving(30);
        assert_eq!((pinned.now(), pinned.leeway()), (NOW, 30));
    }
}
