//! Time offsets for `--time-offset-plus` / `--time-offset-minus`.

/// Parses an offset like fwknop-go: first as a Go duration (`90s`, `2m`,
/// `1h30m`, `1.5h`), then as a plain number of seconds (`30`). Returns
/// nanoseconds.
pub fn parse_time_offset(s: &str) -> Result<i128, String> {
    if s.is_empty() {
        return Ok(0);
    }
    if let Some(ns) = parse_go_duration(s) {
        return Ok(ns);
    }
    if let Some(secs) = scan_leading_int(s) {
        return Ok(i128::from(secs) * 1_000_000_000);
    }
    Err(format!("invalid time offset: {s}"))
}

/// Go's `time.ParseDuration`, in nanoseconds.
fn parse_go_duration(s: &str) -> Option<i128> {
    let (neg, mut rest) = match s.as_bytes().first()? {
        b'-' => (true, &s[1..]),
        b'+' => (false, &s[1..]),
        _ => (false, s),
    };
    if rest == "0" {
        return Some(0);
    }
    if rest.is_empty() {
        return None;
    }
    let mut total: i128 = 0;
    while !rest.is_empty() {
        let int_len = rest.bytes().take_while(u8::is_ascii_digit).count();
        let int_part = &rest[..int_len];
        rest = &rest[int_len..];
        let mut frac_part = "";
        if let Some(after_dot) = rest.strip_prefix('.') {
            let frac_len = after_dot.bytes().take_while(u8::is_ascii_digit).count();
            frac_part = &after_dot[..frac_len];
            rest = &after_dot[frac_len..];
        }
        if int_part.is_empty() && frac_part.is_empty() {
            return None;
        }
        let unit_len = rest
            .bytes()
            .take_while(|c| !c.is_ascii_digit() && *c != b'.')
            .count();
        let unit = &rest[..unit_len];
        rest = &rest[unit_len..];
        let scale: i128 = match unit {
            "ns" => 1,
            "us" | "µs" | "μs" => 1_000,
            "ms" => 1_000_000,
            "s" => 1_000_000_000,
            "m" => 60 * 1_000_000_000,
            "h" => 3600 * 1_000_000_000,
            _ => return None, // includes a missing unit
        };
        let int_val: i128 = if int_part.is_empty() {
            0
        } else {
            int_part.parse().ok()?
        };
        let mut value = int_val.checked_mul(scale)?;
        if !frac_part.is_empty() {
            let digits = frac_part.len().min(30) as u32;
            let frac: i128 = frac_part[..digits as usize].parse().ok()?;
            value += frac * scale / 10i128.pow(digits);
        }
        total = total.checked_add(value)?;
        if total > i128::from(i64::MAX) {
            return None;
        }
    }
    Some(if neg { -total } else { total })
}

/// Like Go's `fmt.Sscanf(s, "%d", &n)`: skips leading spaces, reads an
/// optionally signed integer and ignores the rest.
fn scan_leading_int(s: &str) -> Option<i64> {
    let t = s.trim_start();
    let sign_len = usize::from(t.starts_with(['+', '-']));
    let digits = t[sign_len..].bytes().take_while(u8::is_ascii_digit).count();
    if digits == 0 {
        return None;
    }
    t[..sign_len + digits].parse().ok()
}

#[cfg(test)]
mod tests {
    use super::*;

    const S: i128 = 1_000_000_000;

    #[test]
    fn offsets() {
        let cases = [
            ("30s", 30 * S),
            ("2m", 120 * S),
            ("1h", 3600 * S),
            ("1h30m", 5400 * S),
            ("1.5h", 5400 * S),
            ("500ms", S / 2),
            ("30", 30 * S),
            ("0", 0),
            ("", 0),
            ("-5m", -300 * S),
            ("45abc", 45 * S), // Go's Sscanf("%d") ignores trailing text
            ("1x", S),
        ];
        for (input, want) in cases {
            assert_eq!(parse_time_offset(input), Ok(want), "{input}");
        }
        for bad in ["abc", "m", ".s", "--5"] {
            assert!(parse_time_offset(bad).is_err(), "{bad}");
        }
    }
}
