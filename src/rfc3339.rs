//! Just enough RFC 3339 for the API's `date-time` fields: parsing one into
//! Unix seconds, formatting Unix seconds as UTC, and reading the short
//! durations (`30m`, `12h`, `7d`) a flag like `--expires-in` takes. The
//! calendar arithmetic is Howard Hinnant's proleptic-Gregorian algorithms,
//! so no date crate is needed for a validation and a `now + duration`.

use std::time::{SystemTime, UNIX_EPOCH};

/// Unix seconds now, saturating at zero on a clock set before 1970.
pub fn now() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| i64::try_from(d.as_secs()).unwrap_or(i64::MAX))
        .unwrap_or(0)
}

/// Parse an RFC 3339 timestamp (`2027-01-01T00:00:00Z`,
/// `2027-01-01T09:30:00.5+02:00`) into Unix seconds, dropping any fraction.
/// `T` and `Z` may be lower case, as the RFC allows.
pub fn parse(s: &str) -> Result<i64, String> {
    const SHAPE: &str = "expected an RFC 3339 timestamp like 2027-01-01T00:00:00Z";
    let b = s.as_bytes();
    if b.len() < 20 || !s.is_ascii() {
        return Err(SHAPE.to_string());
    }
    let num = |from: usize, to: usize| -> Result<i64, String> {
        let digits = &s[from..to];
        if !digits.bytes().all(|c| c.is_ascii_digit()) {
            return Err(SHAPE.to_string());
        }
        digits.parse::<i64>().map_err(|_| SHAPE.to_string())
    };
    let sep = |at: usize, want: &[u8]| -> Result<(), String> {
        if want.contains(&b[at].to_ascii_uppercase()) {
            Ok(())
        } else {
            Err(SHAPE.to_string())
        }
    };
    let year = num(0, 4)?;
    sep(4, b"-")?;
    let month = num(5, 7)?;
    sep(7, b"-")?;
    let day = num(8, 10)?;
    sep(10, b"T")?;
    let hour = num(11, 13)?;
    sep(13, b":")?;
    let minute = num(14, 16)?;
    sep(16, b":")?;
    let second = num(17, 19)?;

    let mut at = 19;
    if b[at] == b'.' {
        let start = at + 1;
        at = start;
        while at < b.len() && b[at].is_ascii_digit() {
            at += 1;
        }
        if at == start {
            return Err(SHAPE.to_string());
        }
    }
    let offset = match b.get(at).map(u8::to_ascii_uppercase) {
        Some(b'Z') if at + 1 == b.len() => 0,
        Some(sign @ (b'+' | b'-')) if at + 6 == b.len() => {
            if b[at + 3] != b':' {
                return Err(SHAPE.to_string());
            }
            let oh = num(at + 1, at + 3)?;
            let om = num(at + 4, at + 6)?;
            if oh > 23 || om > 59 {
                return Err("UTC offset must be within ±23:59".to_string());
            }
            let secs = oh * 3600 + om * 60;
            if sign == b'-' { -secs } else { secs }
        }
        _ => return Err(SHAPE.to_string()),
    };

    if !(1..=12).contains(&month) {
        return Err("month must be 01 to 12".to_string());
    }
    if day < 1 || day > i64::from(days_in_month(year, month as u32)) {
        return Err(format!(
            "day must be 01 to {:02}",
            days_in_month(year, month as u32)
        ));
    }
    // 60 allows a leap second, which the RFC permits.
    if hour > 23 || minute > 59 || second > 60 {
        return Err("time must be 00:00:00 to 23:59:60".to_string());
    }
    let days = days_from_civil(year, month as u32, day as u32);
    Ok(days * 86_400 + hour * 3600 + minute * 60 + second - offset)
}

/// `secs` as an RFC 3339 UTC timestamp, `2027-01-01T00:00:00Z`.
pub fn format(secs: i64) -> String {
    let days = secs.div_euclid(86_400);
    let rem = secs.rem_euclid(86_400);
    let (y, m, d) = civil_from_days(days);
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

/// A duration such as `90s`, `30m`, `12h`, `7d`, `2w`, or a run of them
/// (`1d12h`), in seconds. Whitespace between parts is ignored. At most
/// a century, so a typo can't overflow the arithmetic that follows.
pub fn parse_duration(s: &str) -> Result<u64, String> {
    const SHAPE: &str =
        "expected a duration such as 30m, 12h, or 7d (units: s, m, h, d, w; parts may be combined)";
    const MAX: u64 = 100 * 365 * 86_400;
    let mut total: u64 = 0;
    let mut digits = String::new();
    let mut parts = 0;
    for c in s.chars().filter(|c| !c.is_whitespace()) {
        if c.is_ascii_digit() {
            digits.push(c);
            continue;
        }
        let unit = match c {
            's' => 1,
            'm' => 60,
            'h' => 3600,
            'd' => 86_400,
            'w' => 7 * 86_400,
            _ => return Err(SHAPE.to_string()),
        };
        if digits.is_empty() {
            return Err(SHAPE.to_string());
        }
        let n: u64 = digits.parse().map_err(|_| SHAPE.to_string())?;
        total = n
            .checked_mul(unit)
            .and_then(|secs| total.checked_add(secs))
            .filter(|&t| t <= MAX)
            .ok_or_else(|| "duration must be at most 100 years".to_string())?;
        digits.clear();
        parts += 1;
    }
    if parts == 0 || !digits.is_empty() {
        return Err(SHAPE.to_string());
    }
    if total == 0 {
        return Err("duration must be longer than 0 seconds".to_string());
    }
    Ok(total)
}

fn is_leap(y: i64) -> bool {
    (y % 4 == 0 && y % 100 != 0) || y % 400 == 0
}

fn days_in_month(y: i64, m: u32) -> u32 {
    match m {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        _ if is_leap(y) => 29,
        _ => 28,
    }
}

/// Days since 1970-01-01 for a proleptic Gregorian date.
fn days_from_civil(y: i64, m: u32, d: u32) -> i64 {
    let y = if m <= 2 { y - 1 } else { y };
    let era = if y >= 0 { y } else { y - 399 } / 400;
    let yoe = y - era * 400;
    let mp = i64::from((m + 9) % 12);
    let doy = (153 * mp + 2) / 5 + i64::from(d) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    era * 146_097 + doe - 719_468
}

/// The inverse of [`days_from_civil`]: `(year, month, day)`.
fn civil_from_days(z: i64) -> (i64, u32, u32) {
    let z = z + 719_468;
    let era = if z >= 0 { z } else { z - 146_096 } / 146_097;
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = (doy - (153 * mp + 2) / 5 + 1) as u32;
    let m = if mp < 10 { mp + 3 } else { mp - 9 } as u32;
    (if m <= 2 { y + 1 } else { y }, m, d)
}

#[cfg(test)]
mod tests {
    use proptest::prelude::*;

    use super::*;

    #[test]
    fn parses_utc_offsets_and_fractions() {
        assert_eq!(parse("1970-01-01T00:00:00Z").unwrap(), 0);
        assert_eq!(parse("2027-01-01T00:00:00Z").unwrap(), 1_798_761_600);
        assert_eq!(parse("2027-01-01t00:00:00z").unwrap(), 1_798_761_600);
        assert_eq!(parse("2027-01-01T00:00:00.25Z").unwrap(), 1_798_761_600);
        assert_eq!(parse("2027-01-01T02:00:00+02:00").unwrap(), 1_798_761_600);
        assert_eq!(parse("2026-12-31T19:00:00-05:00").unwrap(), 1_798_761_600);
        assert_eq!(parse("2024-02-29T23:59:60Z").unwrap(), 1_709_251_200);
    }

    #[test]
    fn rejects_what_is_not_a_timestamp() {
        for bad in [
            "",
            "2027-01-01",
            "2027-01-01T00:00:00",
            "2027-01-01 00:00:00Z",
            "2027-01-01T00:00:00+0200",
            "2027-01-01T00:00:00+24:00",
            "2027-01-01T00:00:00.Z",
            "2027-13-01T00:00:00Z",
            "2027-02-29T00:00:00Z",
            "2027-04-31T00:00:00Z",
            "2027-01-01T24:00:00Z",
            "2027-01-01T00:60:00Z",
            "2027-01-01T00:00:61Z",
            "tomorrow",
            "２027-01-01T00:00:00Z",
        ] {
            assert!(parse(bad).is_err(), "{bad:?}");
        }
    }

    #[test]
    fn formats_utc() {
        assert_eq!(format(0), "1970-01-01T00:00:00Z");
        assert_eq!(format(1_798_761_600), "2027-01-01T00:00:00Z");
        assert_eq!(format(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(format(-1), "1969-12-31T23:59:59Z");
    }

    #[test]
    fn durations_take_units_and_combine() {
        assert_eq!(parse_duration("90s").unwrap(), 90);
        assert_eq!(parse_duration("30m").unwrap(), 1800);
        assert_eq!(parse_duration("12h").unwrap(), 43_200);
        assert_eq!(parse_duration("7d").unwrap(), 604_800);
        assert_eq!(parse_duration("2w").unwrap(), 1_209_600);
        assert_eq!(parse_duration("1d12h").unwrap(), 129_600);
        assert_eq!(parse_duration("1d 12h").unwrap(), 129_600);
        for bad in [
            "",
            "7",
            "d",
            "7x",
            "7d5",
            "0h",
            "-1d",
            "1.5h",
            "999999999999d",
        ] {
            assert!(parse_duration(bad).is_err(), "{bad:?}");
        }
    }

    proptest! {
        #[test]
        fn format_then_parse_round_trips(secs in -62_000_000_000i64..=250_000_000_000) {
            prop_assert_eq!(parse(&format(secs)).unwrap(), secs);
        }

        #[test]
        fn civil_round_trips(days in -1_000_000i64..=1_000_000) {
            let (y, m, d) = civil_from_days(days);
            prop_assert_eq!(days_from_civil(y, m, d), days);
            prop_assert!((1..=12).contains(&m));
            prop_assert!(d >= 1 && d <= days_in_month(y, m));
        }
    }
}
