//! The replay cache: replay digests of recently decrypted SPA packets.

use std::collections::HashMap;
use std::time::{Duration, Instant};

#[derive(Debug)]
pub struct ReplayCache {
    /// Replay digest → when it may be forgotten (`None`: never).
    entries: HashMap<String, Option<Instant>>,
    ttl: Option<Duration>,
}

impl ReplayCache {
    /// Remembers each replay digest for `ttl`, or forever when `ttl` is
    /// `None`.
    pub fn new(ttl: Option<Duration>) -> ReplayCache {
        ReplayCache {
            entries: HashMap::new(),
            ttl,
        }
    }

    /// The TTL for a given max packet age. A packet is accepted while its
    /// timestamp is within the max packet age either side of now, so it can
    /// stay valid for twice that long after it first arrives. With no max
    /// packet age (0), packets never expire, so neither do replay digests.
    pub fn ttl_for_max_age(max_age_secs: i64) -> Option<Duration> {
        u64::try_from(max_age_secs)
            .ok()
            .filter(|&s| s > 0)
            .map(|s| Duration::from_secs(2 * s))
    }

    /// New entries use `ttl`; existing ones keep their expiry.
    pub fn set_ttl(&mut self, ttl: Option<Duration>) {
        self.ttl = ttl;
    }

    pub fn is_duplicate(&mut self, digest: &str, now: Instant) -> bool {
        match self.entries.get(digest) {
            None => false,
            Some(Some(expires)) if now > *expires => {
                self.entries.remove(digest);
                false
            }
            Some(_) => true,
        }
    }

    pub fn add(&mut self, digest: String, now: Instant) {
        self.entries.insert(digest, self.ttl.map(|ttl| now + ttl));
    }

    /// Forgets expired replay digests.
    pub fn purge(&mut self, now: Instant) {
        self.entries
            .retain(|_, expires| expires.is_none_or(|e| now <= e));
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.entries.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const MIN: Duration = Duration::from_secs(60);

    #[test]
    fn basic() {
        let mut rc = ReplayCache::new(Some(MIN));
        let now = Instant::now();
        assert!(!rc.is_duplicate("abc", now));
        rc.add("abc".into(), now);
        assert!(rc.is_duplicate("abc", now));
        assert!(!rc.is_duplicate("def", now));
    }

    #[test]
    fn expiration() {
        let mut rc = ReplayCache::new(Some(MIN));
        let now = Instant::now();
        rc.add("abc".into(), now);
        assert!(rc.is_duplicate("abc", now + MIN));
        assert!(!rc.is_duplicate("abc", now + MIN + Duration::from_millis(1)));
        assert_eq!(rc.len(), 0, "an expired entry is removed when checked");
    }

    #[test]
    fn many_entries_and_purge() {
        let mut rc = ReplayCache::new(Some(MIN));
        let now = Instant::now();
        for i in 0..100 {
            rc.add(format!("d{i}"), now + Duration::from_secs(i));
        }
        assert_eq!(rc.len(), 100);
        rc.purge(now + MIN + Duration::from_secs(50));
        assert_eq!(rc.len(), 50);
        assert!(rc.is_duplicate("d99", now + MIN + Duration::from_secs(50)));
        assert!(!rc.is_duplicate("d0", now + MIN + Duration::from_secs(50)));
    }

    #[test]
    fn readd_after_expiry() {
        let mut rc = ReplayCache::new(Some(MIN));
        let now = Instant::now();
        rc.add("abc".into(), now);
        let later = now + 2 * MIN;
        assert!(!rc.is_duplicate("abc", later));
        rc.add("abc".into(), later);
        assert!(rc.is_duplicate("abc", later + MIN));
    }

    #[test]
    fn no_max_age_means_digests_never_expire() {
        // fwknop-go used a TTL of 0 here, so every replayed packet was
        // accepted once the age check was turned off.
        assert_eq!(ReplayCache::ttl_for_max_age(0), None);
        assert_eq!(
            ReplayCache::ttl_for_max_age(120),
            Some(Duration::from_secs(240))
        );
        let mut rc = ReplayCache::new(None);
        let now = Instant::now();
        rc.add("abc".into(), now);
        rc.purge(now + 1000 * MIN);
        assert!(rc.is_duplicate("abc", now + 1000 * MIN));
    }
}
