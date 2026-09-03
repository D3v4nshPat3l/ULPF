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
        TimeFormat::Clf => parse_clf(value.as_str()?),
        TimeFormat::Rfc3164 => parse_rfc3164(value.as_str()?),
    }
}

/// Parse an RFC 3164 syslog timestamp: `Mar 13 04:10:10`.
///
/// The format has no year. The current year is assumed, matching what syslog
/// collectors do; for a historical replay this puts events in the wrong year,
/// which is why the receipt time is always recorded separately in
/// `metadata.logged_time`.
fn parse_rfc3164(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let s = s.trim();
    let mut parts = s.split_whitespace();
    let mon_name = parts.next()?;
    let day: u8 = parts.next()?.parse().ok()?;
    let clock = parts.next()?;
    if parts.next().is_some() {
        return None;
    }
    let month = MONTHS.iter().position(|m| *m == mon_name)? as u8 + 1;

    let mut c = clock.split(':');
    let hour: u8 = c.next()?.parse().ok()?;
    let minute: u8 = c.next()?.parse().ok()?;
    let second: u8 = c.next()?.parse().ok()?;
    if c.next().is_some() {
        return None;
    }

    let year = OffsetDateTime::now_utc().year();
    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let clock = time::Time::from_hms(hour, minute, second).ok()?;
    Some(
        PrimitiveDateTime::new(date, clock)
            .assume_utc()
            .unix_timestamp_nanos() as i64,
    )
}

/// Parse NCSA Common Log Format: `10/Oct/2000:13:55:36 -0700`.
///
/// Unlike the other civil formats this one carries an explicit UTC offset, so
/// the result is exact rather than assumed.
fn parse_clf(s: &str) -> Option<i64> {
    const MONTHS: [&str; 12] = [
        "Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec",
    ];
    let s = s.trim();
    let (stamp, offset) = match s.split_once(' ') {
        Some((a, b)) => (a, Some(b)),
        None => (s, None),
    };

    let (date, clock) = stamp.split_once(':')?;
    let mut d = date.split('/');
    let day: u8 = d.next()?.parse().ok()?;
    let mon_name = d.next()?;
    let year: i32 = d.next()?.parse().ok()?;
    if d.next().is_some() {
        return None;
    }
    let month = MONTHS.iter().position(|m| *m == mon_name)? as u8 + 1;

    let mut c = clock.split(':');
    let hour: u8 = c.next()?.parse().ok()?;
    let minute: u8 = c.next()?.parse().ok()?;
    let second: u8 = c.next()?.parse().ok()?;
    if c.next().is_some() {
        return None;
    }

    // Offset is +HHMM / -HHMM.
    let offset_seconds: i64 = match offset {
        None => 0,
        Some(o) => {
            let o = o.trim();
            let sign = match o.as_bytes().first()? {
                b'+' => 1,
                b'-' => -1,
                _ => return None,
            };
            let digits = &o[1..];
            if digits.len() != 4 || !digits.bytes().all(|b| b.is_ascii_digit()) {
                return None;
            }
            let h: i64 = digits[..2].parse().ok()?;
            let m: i64 = digits[2..].parse().ok()?;
            sign * (h * 3600 + m * 60)
        }
    };

    let date =
        time::Date::from_calendar_date(year, time::Month::try_from(month).ok()?, day).ok()?;
    let clock = time::Time::from_hms(hour, minute, second).ok()?;
    let naive = PrimitiveDateTime::new(date, clock)
        .assume_utc()
        .unix_timestamp_nanos() as i64;
    naive.checked_sub(offset_seconds.checked_mul(1_000_000_000)?)
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
    fn rfc3164_timestamps_parse_with_the_current_year() {
        // Real OpenSSH line stamp.
        let got = parse_time(&v("Dec 10 06:55:46"), TimeFormat::Rfc3164).unwrap();
        let year = time::OffsetDateTime::now_utc().year();
        let expected = parse_time(
            &Value::owned(format!("{year}-12-10T06:55:46Z")),
            TimeFormat::Rfc3339,
        )
        .unwrap();
        assert_eq!(got, expected);
    }

    #[test]
    fn rfc3164_accepts_a_space_padded_day() {
        assert!(parse_time(&v("Mar  3 04:10:10"), TimeFormat::Rfc3164).is_some());
    }

    #[test]
    fn rfc3164_rejects_junk() {
        assert_eq!(parse_time(&v("Xxx 13 04:10:10"), TimeFormat::Rfc3164), None);
        assert_eq!(parse_time(&v("Mar 13"), TimeFormat::Rfc3164), None);
    }

    #[test]
    fn clf_timestamps_honour_their_offset() {
        // A real Apache line from the SotM34 capture.
        let got = parse_time(&v("13/Mar/2005:04:05:47 -0500"), TimeFormat::Clf).unwrap();
        // -0500 means the UTC instant is five hours later.
        let utc = parse_time(&v("2005-03-13T09:05:47Z"), TimeFormat::Rfc3339).unwrap();
        assert_eq!(got, utc);
    }

    #[test]
    fn clf_without_an_offset_is_read_as_utc() {
        let got = parse_time(&v("13/Mar/2005:04:05:47"), TimeFormat::Clf).unwrap();
        let utc = parse_time(&v("2005-03-13T04:05:47Z"), TimeFormat::Rfc3339).unwrap();
        assert_eq!(got, utc);
    }

    #[test]
    fn clf_rejects_a_bad_month() {
        assert_eq!(
            parse_time(&v("13/Xxx/2005:04:05:47 -0500"), TimeFormat::Clf),
            None
        );
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
