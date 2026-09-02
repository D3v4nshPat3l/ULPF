//! Timestamp normalization.
//!
//! OCSF `time` is nanoseconds since the Unix epoch. Devices supply almost
//! anything else: epoch seconds, epoch milliseconds, RFC 3339, and two
//! different punctuations of `YYYY MM DD HH:MM:SS`. Everything converges here.
//!
//! Timestamps without a zone are read as UTC rather than local time. An
//! air-gapped collector and the device it collects from are frequently in
//! different zones, and silently applying the *collector's* zone would shift
//! every event by a whole number of hours — the kind of error that survives all
//! the way to an incident timeline before anyone notices.

use time::{OffsetDateTime, PrimitiveDateTime};
use ulpf_core::Value;

use crate::spec::TimeFormat;

/// Convert a device timestamp to nanoseconds since the Unix epoch.
pub fn parse_time(value: &Value<'_>, format: TimeFormat) -> Option<i64> {
    match format {
        TimeFormat::EpochS => value.as_int()?.checked_mul(1_000_000_000),
        TimeFormat::EpochMs => value.as_int()?.checked_mul(1_000_000),
        TimeFormat::EpochUs => value.as_int()?.checked_mul(1_000),
        TimeFormat::EpochNs => value.as_int(),
        TimeFormat::Rfc3339 => {
            let s = value.as_str()?;
            OffsetDateTime::parse(s, &time::format_description::well_known::Rfc3339)
                .ok()
                .map(|dt| dt.unix_timestamp_nanos() as i64)
        }
        TimeFormat::DateTime => parse_civil(value.as_str()?, '-'),
        TimeFormat::SlashDateTime => parse_civil(value.as_str()?, '/'),
    }
}

/// Parse `YYYY<sep>MM<sep>DD HH:MM:SS[.fraction]` as UTC.
fn parse_civil(s: &str, sep: char) -> Option<i64> {
    let s = s.trim();
    let (date, rest) = s.split_once([' ', 'T'])?;

    let mut parts = date.split(sep);
    let year: i32 = parts.next()?.parse().ok()?;
    let month: u8 = parts.next()?.parse().ok()?;
    let day: u8 = parts.next()?.parse().ok()?;
    if parts.next().is_some() {
        return None;
    }

    // Drop a trailing zone marker; these formats are defined as local device
    // time and carry no offset, so anything here is decoration.
    let time_part = rest.trim_end_matches('Z');
    let (clock, fraction) = match time_part.split_once('.') {
        Some((c, f)) => (c, Some(f)),
        None => (time_part, None),
    };

    let mut clock_parts = clock.split(':');
    let hour: u8 = clock_parts.next()?.parse().ok()?;
    let minute: u8 = clock_parts.next()?.parse().ok()?;
    let second: u8 = clock_parts.next().unwrap_or("0").parse().ok()?;
    if clock_parts.next().is_some() {
        return None;
    }

    let nanos: u32 = match fraction {
        None => 0,
        Some(f) => {
            let digits: String = f.chars().take_while(char::is_ascii_digit).collect();
            if digits.is_empty() {
                0
            } else {
                let padded = format!("{digits:0<9}");
                padded.get(..9)?.parse().ok()?
            }
        }
    };

    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let clock = time::Time::from_hms_nano(hour, minute, second, nanos).ok()?;
    Some(
        PrimitiveDateTime::new(date, clock)
            .assume_utc()
            .unix_timestamp_nanos() as i64,
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v(s: &str) -> Value<'_> {
        Value::borrowed(s)
    }

    #[test]
    fn epoch_seconds_scale_to_nanoseconds() {
        assert_eq!(
            parse_time(&v("1756636800"), TimeFormat::EpochS),
            Some(1_756_636_800_000_000_000)
        );
    }

    #[test]
    fn epoch_millis_and_micros_scale() {
        assert_eq!(
            parse_time(&v("1756636800123"), TimeFormat::EpochMs),
            Some(1_756_636_800_123_000_000)
        );
        assert_eq!(
            parse_time(&v("1756636800123456"), TimeFormat::EpochUs),
            Some(1_756_636_800_123_456_000)
        );
        assert_eq!(
            parse_time(&v("1756636800123456789"), TimeFormat::EpochNs),
            Some(1_756_636_800_123_456_789)
        );
    }

    #[test]
    fn rfc3339_with_offset_is_converted_to_utc() {
        // 10:23:45+05:30 is 04:53:45Z.
        let with_offset = parse_time(&v("2026-08-31T10:23:45+05:30"), TimeFormat::Rfc3339).unwrap();
        let as_utc = parse_time(&v("2026-08-31T04:53:45Z"), TimeFormat::Rfc3339).unwrap();
        assert_eq!(with_offset, as_utc);
    }

    #[test]
    fn fortigate_style_datetime_parses_as_utc() {
        let got = parse_time(&v("2026-08-31 10:23:45"), TimeFormat::DateTime).unwrap();
        let expected = parse_time(&v("2026-08-31T10:23:45Z"), TimeFormat::Rfc3339).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn pan_os_slash_datetime_parses() {
        let got = parse_time(&v("2026/08/31 10:23:45"), TimeFormat::SlashDateTime).unwrap();
        let expected = parse_time(&v("2026-08-31T10:23:45Z"), TimeFormat::Rfc3339).unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn fractional_seconds_are_kept_at_nanosecond_resolution() {
        let got = parse_time(&v("2026-08-31 10:23:45.123"), TimeFormat::DateTime).unwrap();
        let whole = parse_time(&v("2026-08-31 10:23:45"), TimeFormat::DateTime).unwrap();
        assert_eq!(got - whole, 123_000_000);
    }

    #[test]
    fn a_t_separator_is_accepted_in_civil_format() {
        let t = parse_time(&v("2026-08-31T10:23:45"), TimeFormat::DateTime).unwrap();
        let space = parse_time(&v("2026-08-31 10:23:45"), TimeFormat::DateTime).unwrap();
        assert_eq!(t, space);
    }

    #[test]
    fn garbage_returns_none_so_the_default_applies() {
        assert_eq!(parse_time(&v("not a time"), TimeFormat::DateTime), None);
        assert_eq!(parse_time(&v(""), TimeFormat::Rfc3339), None);
        assert_eq!(
            parse_time(&v("2026-13-45 99:99:99"), TimeFormat::DateTime),
            None
        );
    }

    #[test]
    fn out_of_range_epoch_does_not_panic_on_overflow() {
        assert_eq!(
            parse_time(&v("9223372036854775807"), TimeFormat::EpochS),
            None
        );
    }

    #[test]
    fn epoch_seconds_accept_an_integer_value_not_just_a_string() {
        assert_eq!(
            parse_time(&Value::Int(1_756_636_800), TimeFormat::EpochS),
            Some(1_756_636_800_000_000_000)
        );
    }
}
