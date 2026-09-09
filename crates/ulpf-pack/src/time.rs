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

/// Recognise a timestamp at the head of an arbitrary line and return it in
/// nanoseconds, together with whether the format stated a year.
///
/// This exists for records no pack claims. Such a record used to be stamped
/// with the moment ULPF received it, which is a different fact from when the
/// event happened and reads as the latter: replaying a 2005 capture produced
/// events dated today. An unidentified record can still carry a real event
/// time whenever the line states one unambiguously, and this says which
/// formats count as unambiguous.
///
/// Deliberately narrow. It tries only shapes that appear at the very start of
/// a line and cannot be confused with something else, because a wrong
/// timestamp is worse than an honest fallback: it puts an event in the wrong
/// place on an incident timeline, and nothing downstream can tell.
pub fn detect_leading_time(line: &str) -> Option<DetectedTime> {
    let line = line.trim_start();

    // RFC 5424 / RFC 3339 at the head, optionally behind a syslog priority:
    // "<134>2026-01-01T00:00:00Z ..." or "2026-01-01T00:00:00+05:30 ...".
    let after_pri = match line.strip_prefix('<') {
        Some(rest) => rest.split_once('>').map(|(_, r)| r).unwrap_or(line),
        None => line,
    };
    if let Some(token) = after_pri.split_whitespace().next() {
        if token.len() >= 20 && token.as_bytes()[4] == b'-' {
            if let Some(ns) = parse_time(&Value::Str(token.into()), TimeFormat::Rfc3339) {
                return Some(DetectedTime {
                    nanos: ns,
                    year_stated: true,
                });
            }
        }
    }

    // "2015-07-29 19:52:04,792" -- a date and a clock as two separate tokens
    // at the head. This is what log4j, java.util.logging and Python's logging
    // module emit by default, so it covers most application logging in
    // existence; Zookeeper, Hadoop and Spark captures are all this shape.
    // Recognised only as the first two tokens, both fully formed, which no
    // other construct looks like.
    {
        let mut tokens = after_pri.split_whitespace();
        if let (Some(date), Some(clock)) = (tokens.next(), tokens.next()) {
            if looks_like_date(date) && looks_like_clock(clock) {
                // log4j writes the fraction after a comma; parse_civil expects
                // the decimal point that every other format uses.
                let joined = format!("{date} {}", clock.replacen(',', ".", 1));
                let format = if date.as_bytes()[4] == b'/' {
                    TimeFormat::SlashDateTime
                } else {
                    TimeFormat::DateTime
                };
                if let Some(ns) = parse_time(&Value::Str(joined.into()), format) {
                    return Some(DetectedTime {
                        nanos: ns,
                        year_stated: true,
                    });
                }
            }
        }
    }

    // Common Log Format, as Apache and many proxies write it:
    // '... [24/Feb/2005:16:36:18 -0500] ...'. Anchored on the bracket so a
    // bare date elsewhere in the message cannot be mistaken for it.
    if let Some(open) = line.find('[') {
        if let Some(close) = line[open..].find(']') {
            let inner = &line[open + 1..open + close];
            if inner.len() >= 20 && inner.as_bytes().get(2) == Some(&b'/') {
                if let Some(ns) = parse_time(&Value::Str(inner.into()), TimeFormat::Clf) {
                    return Some(DetectedTime {
                        nanos: ns,
                        year_stated: true,
                    });
                }
            }
        }
    }

    // RFC 3164 syslog: "Feb 27 02:25:52". Carries no year, so the value is
    // usable but the caller must be told the year was assumed rather than
    // read -- on a historical replay it lands in the wrong one.
    let head: Vec<&str> = after_pri.split_whitespace().take(3).collect();
    if head.len() == 3 {
        let joined = head.join(" ");
        if let Some(ns) = parse_time(&Value::Str(joined.into()), TimeFormat::Rfc3164) {
            return Some(DetectedTime {
                nanos: ns,
                year_stated: false,
            });
        }
    }

    // A JSON object states its timestamp in a named field rather than at the
    // head. That is not a guess: the line parses as JSON, the key is one the
    // logging world has settled on, and the value has to parse strictly as
    // RFC 3339 or it is ignored. JSON is most of modern application logging,
    // so without this the whole shape falls back to receipt time.
    if line.starts_with('{') {
        if let Ok(serde_json::Value::Object(map)) = serde_json::from_str::<serde_json::Value>(line)
        {
            const TIME_KEYS: [&str; 6] = [
                "ts",
                "time",
                "timestamp",
                "@timestamp",
                "eventTime",
                "event_time",
            ];
            for key in TIME_KEYS {
                let Some(serde_json::Value::String(v)) = map.get(key) else {
                    continue;
                };
                if let Some(ns) = parse_time(&Value::Str(v.as_str().into()), TimeFormat::Rfc3339) {
                    return Some(DetectedTime {
                        nanos: ns,
                        year_stated: true,
                    });
                }
            }
        }
    }

    // Delimited formats -- CEF, LEEF and the many in-house pipe or tab layouts
    // -- put the timestamp in a column rather than at the head. Accepted only
    // when *exactly one* field parses strictly as RFC 3339: one such field is
    // the event time, and two mean the line distinguishes between times this
    // code cannot tell apart, such as first-seen and last-seen. Guessing
    // between them would put events in the wrong place on a timeline, so it
    // declines instead.
    for delim in ['|', '\t', ';'] {
        if !line.contains(delim) {
            continue;
        }
        let mut found: Option<i64> = None;
        let mut count = 0usize;
        for field in line.split(delim) {
            let field = field.trim();
            if field.len() < 20 {
                continue;
            }
            if let Some(ns) = parse_time(&Value::Str(field.into()), TimeFormat::Rfc3339) {
                count += 1;
                found = Some(ns);
            }
        }
        if count == 1 {
            return Some(DetectedTime {
                nanos: found?,
                year_stated: true,
            });
        }
    }

    None
}

/// `YYYY-MM-DD` or `YYYY/MM/DD`, exactly.
fn looks_like_date(t: &str) -> bool {
    let b = t.as_bytes();
    t.len() == 10
        && b[..4].iter().all(u8::is_ascii_digit)
        && (b[4] == b'-' || b[4] == b'/')
        && b[4] == b[7]
        && b[5..7].iter().all(u8::is_ascii_digit)
        && b[8..10].iter().all(u8::is_ascii_digit)
}

/// `HH:MM:SS`, optionally with a `,mmm` or `.mmm` fraction.
fn looks_like_clock(t: &str) -> bool {
    let base = t.split([',', '.']).next().unwrap_or(t);
    let b = base.as_bytes();
    base.len() == 8
        && b[2] == b':'
        && b[5] == b':'
        && b[..2].iter().all(u8::is_ascii_digit)
        && b[3..5].iter().all(u8::is_ascii_digit)
        && b[6..8].iter().all(u8::is_ascii_digit)
}

/// A timestamp read from a line, and whether its format stated the year.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DetectedTime {
    pub nanos: i64,
    /// False for RFC 3164, which has no year field at all.
    pub year_stated: bool,
}

#[cfg(test)]
mod detect_tests {
    use super::*;

    #[test]
    fn rfc3339_at_the_head_is_read_with_its_year() {
        let d = detect_leading_time("2005-02-24T16:36:18Z something happened").unwrap();
        assert!(d.year_stated);
        // 2005-02-24T16:36:18Z
        assert_eq!(d.nanos, 1_109_262_978_000_000_000);
    }

    #[test]
    fn a_syslog_priority_does_not_hide_the_timestamp() {
        let d = detect_leading_time("<134>2005-02-24T16:36:18Z msg").unwrap();
        assert_eq!(d.nanos, 1_109_262_978_000_000_000);
    }

    #[test]
    fn common_log_format_is_read_from_its_brackets() {
        let line = r#"218.23.48.35 - - [24/Feb/2005:16:36:18 -0500] "GET / HTTP/1.1" 403 2898"#;
        let d = detect_leading_time(line).unwrap();
        assert!(d.year_stated);
        // 16:36:18 -0500 is 21:36:18 UTC.
        assert_eq!(d.nanos, 1_109_280_978_000_000_000);
    }

    #[test]
    fn rfc3164_is_usable_but_reports_that_it_stated_no_year() {
        let d = detect_leading_time("Feb 27 02:25:52 bridge kernel: INBOUND TCP").unwrap();
        assert!(!d.year_stated, "RFC 3164 has no year field");
    }

    #[test]
    fn prose_is_not_a_timestamp() {
        // The failure that matters: inventing a time for a line that has none
        // puts the event somewhere false on a timeline.
        assert!(detect_leading_time("the quick brown fox jumped").is_none());
        assert!(detect_leading_time("").is_none());
        assert!(detect_leading_time("ERROR could not connect to host").is_none());
    }

    #[test]
    fn a_json_log_states_its_time_in_a_named_field() {
        let line = r#"{"ts":"2021-11-05T22:10:01Z","unit":"hvac-7","note":"compressor fault"}"#;
        let d = detect_leading_time(line).unwrap();
        assert!(d.year_stated);
        assert_eq!(d.nanos, 1_636_150_201_000_000_000);
    }

    #[test]
    fn the_other_common_json_time_keys_work_too() {
        for key in ["time", "timestamp", "@timestamp", "eventTime", "event_time"] {
            let line = format!(r#"{{"{key}":"2021-11-05T22:10:01Z","x":1}}"#);
            assert!(
                detect_leading_time(&line).is_some(),
                "key {key} was not recognised"
            );
        }
    }

    #[test]
    fn a_json_field_that_is_not_a_timestamp_is_left_alone() {
        // "ts" holding something unparseable must not become a time, and must
        // not stop the record being processed.
        assert!(detect_leading_time(r#"{"ts":"yesterday","x":1}"#).is_none());
        assert!(detect_leading_time(r#"{"ts":12345,"x":1}"#).is_none());
        assert!(detect_leading_time(r#"{"note":"no time here"}"#).is_none());
    }

    #[test]
    fn malformed_json_does_not_panic() {
        assert!(detect_leading_time(r#"{"ts":"2021-11-05T22:10:01Z""#).is_none());
        assert!(detect_leading_time("{").is_none());
    }

    #[test]
    fn the_log4j_shape_is_read_including_its_comma_fraction() {
        // Zookeeper, Hadoop, Spark and Python logging all write this.
        let d =
            detect_leading_time("2015-07-29 19:52:04,792 - INFO  [main] - Closed socket").unwrap();
        assert!(d.year_stated);
        // 2015-07-29T19:52:04.792Z
        assert_eq!(d.nanos, 1_438_199_524_792_000_000);
    }

    #[test]
    fn the_same_shape_with_slashes_and_no_fraction() {
        let d = detect_leading_time("2015/07/29 19:52:04 something").unwrap();
        assert_eq!(d.nanos, 1_438_199_524_000_000_000);
    }

    #[test]
    fn a_date_without_a_clock_after_it_is_not_a_timestamp() {
        assert!(detect_leading_time("2015-07-29 was the outage").is_none());
        assert!(detect_leading_time("2015-07-2 19:52:04 short date").is_none());
    }

    #[test]
    fn a_delimited_line_yields_its_single_timestamp_column() {
        let line = "ZZTOP|2019-06-01T09:15:00+02:00|sensor-14|threshold exceeded|10.44.9.2";
        let d = detect_leading_time(line).unwrap();
        assert!(d.year_stated);
        // 09:15:00+02:00 is 07:15:00 UTC.
        assert_eq!(d.nanos, 1_559_373_300_000_000_000);
    }

    #[test]
    fn two_timestamp_columns_are_refused_rather_than_guessed_between() {
        // first-seen and last-seen, or created and modified. Picking one would
        // be a coin toss that lands on an incident timeline.
        let line = "SENSOR|2019-06-01T09:15:00Z|2019-06-01T09:47:12Z|flow closed";
        assert!(detect_leading_time(line).is_none());
    }

    #[test]
    fn a_date_buried_in_prose_is_not_taken_as_the_event_time() {
        assert!(detect_leading_time("renewal due 2026-01-01T00:00:00Z per policy").is_none());
    }
}
