//! Timestamps formatted like fwknop-go prints them, in the local time zone.

use jiff::Timestamp;
use jiff::tz::TimeZone;

/// Go's `time.RFC3339` in local time: `2026-11-04T14:57:31-05:00`, or with
/// `Z` when the local offset is zero.
pub fn rfc3339_local(unix_seconds: i64) -> String {
    rfc3339_in(unix_seconds, &TimeZone::system())
}

pub fn rfc3339_in(unix_seconds: i64, tz: &TimeZone) -> String {
    let Ok(ts) = Timestamp::from_second(unix_seconds) else {
        return unix_seconds.to_string();
    };
    let zoned = ts.to_zoned(tz.clone());
    if zoned.offset().seconds() == 0 {
        zoned.strftime("%Y-%m-%dT%H:%M:%SZ").to_string()
    } else {
        zoned.strftime("%Y-%m-%dT%H:%M:%S%:z").to_string()
    }
}

/// Go's `log.LstdFlags` prefix in local time: `2026/11/04 14:57:31`.
pub fn log_timestamp_now() -> String {
    jiff::Zoned::now().strftime("%Y/%m/%d %H:%M:%S").to_string()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rfc3339_uses_z_for_utc_and_offsets_otherwise() {
        assert_eq!(
            rfc3339_in(1_775_331_907, &TimeZone::UTC),
            "2026-04-04T19:45:07Z"
        );
        let est = TimeZone::fixed(jiff::tz::offset(-5));
        assert_eq!(rfc3339_in(1_775_331_907, &est), "2026-04-04T14:45:07-05:00");
    }

    #[test]
    fn log_timestamp_shape() {
        let s = log_timestamp_now();
        assert_eq!(s.len(), 19);
        assert_eq!(&s[4..5], "/");
        assert_eq!(&s[10..11], " ");
    }
}
