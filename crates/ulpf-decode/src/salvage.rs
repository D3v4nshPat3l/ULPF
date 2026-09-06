//! Universal salvage extraction: getting something out of a line no pack claims.
//!
//! This is the answer to the part of PS 26156 that the Source Pack mechanism
//! does not reach. Packs handle sources someone has onboarded; the statement
//! asks for a framework that converts *any* perimeter log "regardless of
//! source, format, vendor, or technology", and complains specifically that
//! security teams "spend substantial effort developing source-specific
//! parsers". A record from a device nobody has written a pack for should still
//! be more than an opaque string.
//!
//! Before this module, an unidentified record became a minimal OCSF event
//! carrying its raw text and nothing else: countable and retrievable, but not
//! searchable by indicator. An analyst hunting an address could not find it,
//! because no field held that address.
//!
//! Salvage extraction reads any line and pulls out the entities that appear in
//! perimeter telemetry regardless of vendor — addresses, ports, MAC addresses,
//! URLs, email addresses, hostnames — plus any `key=value` pairs it finds. The
//! result populates OCSF `observables`, so an unknown record is immediately
//! searchable by the things an investigator actually pivots on.
//!
//! # What this deliberately is not
//!
//! It does not guess an event class, an activity, or a direction. A pack knows
//! that FortiGate's `srcip` is the *source* and `dstip` is the destination;
//! this module sees two addresses and says so without inventing a role. That
//! restraint is the point: a wrong `src_endpoint.ip` is worse than an absent
//! one, because a detection rule will act on it. Salvage output is evidence
//! that something is present, never an assertion about what it means.
//!
//! It is also fully deterministic — no model, no inference, no per-event
//! network call — so it holds in an air-gapped deployment and produces the
//! same output for the same bytes forever.

use std::collections::BTreeSet;

/// One entity recovered from an unparsed line.
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct Salvaged {
    /// OCSF `observable.type_id`.
    pub type_id: u8,
    /// The literal text found.
    pub value: String,
}

/// OCSF observable type ids used here. Mirrors `ulpf_ocsf::types::ObservableType`,
/// which this crate cannot depend on without a cycle.
mod ty {
    pub const HOSTNAME: u8 = 1;
    pub const IP_ADDRESS: u8 = 2;
    pub const MAC_ADDRESS: u8 = 3;
    pub const EMAIL: u8 = 5;
    pub const URL: u8 = 6;
    pub const PORT: u8 = 11;
}

/// Cap on entities returned from one line.
///
/// A pathological record — a routing table dump, a base64 blob that happens to
/// contain dotted quads — should not be able to attach thousands of
/// observables to one event and turn the output stream into a memory problem.
const MAX_PER_RECORD: usize = 32;

/// Extract every recognisable entity from an arbitrary line.
///
/// Results are deduplicated and ordered, so the same input always produces the
/// same list. That matters more than it looks: the event is canonicalized and
/// hashed, so a nondeterministic order would produce a different fingerprint
/// for the same bytes and break verification.
pub fn salvage(input: &str) -> Vec<Salvaged> {
    let mut found: BTreeSet<Salvaged> = BTreeSet::new();

    for token in input.split(|c: char| {
        c.is_whitespace() || matches!(c, '|' | ',' | ';' | '(' | ')' | '[' | ']' | '<' | '>' | '"')
    }) {
        if token.is_empty() {
            continue;
        }
        classify(token, &mut found);
        if found.len() >= MAX_PER_RECORD {
            break;
        }
    }

    found.into_iter().take(MAX_PER_RECORD).collect()
}

/// Classify one whitespace/delimiter-separated token.
fn classify(token: &str, out: &mut BTreeSet<Salvaged>) {
    // URLs are tested before the `key=value` split, because a query string
    // contains `=` and splitting on the first one reduced
    // `http://example.com/a?b=1` to `1`.
    if is_url(token) {
        push(out, ty::URL, token);
        return;
    }

    // A `key=value` pair contributes its value, not the whole token. Devices
    // write `srcip=10.0.0.1`, and the address is the part worth indexing.
    let candidate = match token.split_once('=') {
        Some((_, value)) if !value.is_empty() => value,
        _ => token,
    };
    let candidate = candidate.trim_matches(|c: char| matches!(c, '\'' | '"' | ',' | ';'));
    if candidate.is_empty() {
        return;
    }

    if is_url(candidate) {
        push(out, ty::URL, candidate);
        return;
    }

    if is_email(candidate) {
        push(out, ty::EMAIL, candidate);
        return;
    }

    if is_mac(candidate) {
        push(out, ty::MAC_ADDRESS, candidate);
        return;
    }

    // A bare IPv6 address is tested before the `host:port` split. Splitting
    // `2001:db8::1` on its last colon yields host `2001:db8:` and port `1`,
    // both of which pass their own tests, and the address is lost. IPv6 with a
    // port is written `[2001:db8::1]:443`, whose brackets this module already
    // treats as delimiters.
    if is_ipv6(candidate) {
        push(out, ty::IP_ADDRESS, candidate);
        return;
    }

    // `10.0.0.1:443` is the single most common way an endpoint is written, and
    // splitting it yields two observables an analyst can pivot on separately.
    if let Some((host, port)) = candidate.rsplit_once(':') {
        if is_port(port) && !host.is_empty() {
            let host = host.trim_matches(|c: char| matches!(c, '[' | ']'));
            if is_ipv4(host) {
                push(out, ty::IP_ADDRESS, host);
                push(out, ty::PORT, port);
                return;
            }
            if is_hostname(host) {
                push(out, ty::HOSTNAME, host);
                push(out, ty::PORT, port);
                return;
            }
        }
    }

    if is_ipv4(candidate) {
        push(out, ty::IP_ADDRESS, candidate);
        return;
    }

    if is_hostname(candidate) {
        push(out, ty::HOSTNAME, candidate);
    }
}

fn push(out: &mut BTreeSet<Salvaged>, type_id: u8, value: &str) {
    out.insert(Salvaged {
        type_id,
        value: value.to_string(),
    });
}

fn is_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://") || s.starts_with("ftp://")
}

fn is_ipv4(s: &str) -> bool {
    let mut parts = 0;
    for octet in s.split('.') {
        parts += 1;
        if parts > 4 || octet.is_empty() || octet.len() > 3 {
            return false;
        }
        if !octet.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        if octet.parse::<u16>().map(|n| n > 255).unwrap_or(true) {
            return false;
        }
    }
    parts == 4
}

/// Accept the IPv6 forms that appear in logs, without reimplementing the RFC.
///
/// Requires at least two colons and only hex digits or colons, which excludes
/// clock times (`10:23:45`) — the single most common false positive, since a
/// syslog line carries one on every record.
fn is_ipv6(s: &str) -> bool {
    let colons = s.bytes().filter(|b| *b == b':').count();
    if colons < 2 || s.len() < 3 {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_hexdigit() || b == b':' || b == b'.')
    {
        return false;
    }
    // A time is all decimal digits and colons; an address needs a hex letter
    // or a `::` run to be distinguishable from one.
    s.contains("::") || s.bytes().any(|b| b.is_ascii_alphabetic())
}

fn is_mac(s: &str) -> bool {
    let sep = if s.matches(':').count() == 5 {
        ':'
    } else if s.matches('-').count() == 5 {
        '-'
    } else {
        return false;
    };
    s.split(sep)
        .all(|part| part.len() == 2 && part.bytes().all(|b| b.is_ascii_hexdigit()))
}

fn is_port(s: &str) -> bool {
    !s.is_empty()
        && s.len() <= 5
        && s.bytes().all(|b| b.is_ascii_digit())
        && s.parse::<u32>()
            .map(|n| n > 0 && n <= 65535)
            .unwrap_or(false)
}

/// A conservative hostname test.
///
/// Requires a dot and a plausible alphabetic TLD, so ordinary dotted words in
/// prose — `state.` at the end of a sentence, a version like `1.2.3` — do not
/// become hostnames. Over-reporting here would be worse than silence: a
/// hunting query for a domain must not match a log line that never held one.
fn is_hostname(s: &str) -> bool {
    if s.len() < 4 || s.len() > 253 || !s.contains('.') {
        return false;
    }
    if s.starts_with('.') || s.ends_with('.') || s.contains("..") {
        return false;
    }
    if !s
        .bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_'))
    {
        return false;
    }
    // The last label must look like a TLD: alphabetic and at least two
    // characters. That is what separates `mail.example.com` from `1.2.3.4`
    // and from a file name like `core.2481`.
    let tld = s.rsplit('.').next().unwrap_or("");
    tld.len() >= 2 && tld.bytes().all(|b| b.is_ascii_alphabetic())
}

fn is_email(s: &str) -> bool {
    let Some((local, domain)) = s.split_once('@') else {
        return false;
    };
    !local.is_empty()
        && local.len() <= 64
        && is_hostname(domain)
        && local
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'-' | b'_' | b'+'))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn values(input: &str, type_id: u8) -> Vec<String> {
        salvage(input)
            .into_iter()
            .filter(|s| s.type_id == type_id)
            .map(|s| s.value)
            .collect()
    }

    #[test]
    fn recovers_addresses_from_a_format_no_pack_knows() {
        // An invented vendor line. Nothing about this format is known, and the
        // addresses are still recoverable.
        let line = "ACMEGW[4412] flow-end 10.2.4.7:44321 -> 93.184.216.34:443 verdict=allow";
        assert_eq!(
            values(line, ty::IP_ADDRESS),
            vec!["10.2.4.7", "93.184.216.34"]
        );
        // Sorted, not in order of appearance: the set is ordered so the same
        // bytes always yield the same fingerprint.
        assert_eq!(values(line, ty::PORT), vec!["443", "44321"]);
    }

    #[test]
    fn takes_the_value_of_a_key_value_pair() {
        let found = values("srcip=10.0.0.1 dstip=8.8.8.8", ty::IP_ADDRESS);
        assert_eq!(found, vec!["10.0.0.1", "8.8.8.8"]);
    }

    #[test]
    fn a_syslog_clock_is_not_an_ipv6_address() {
        // The most likely false positive in the entire module: every syslog
        // line carries a time, and a naive colon-count test calls it IPv6.
        assert!(salvage("Sep 22 10:23:45 host daemon: up")
            .iter()
            .all(|s| s.type_id != ty::IP_ADDRESS));
    }

    #[test]
    fn recognises_ipv6_and_mac_addresses() {
        assert_eq!(
            values("src=2001:db8::1 mac=00:1b:44:11:3a:b7", ty::IP_ADDRESS),
            vec!["2001:db8::1"]
        );
        assert_eq!(
            values("src=2001:db8::1 mac=00:1b:44:11:3a:b7", ty::MAC_ADDRESS),
            vec!["00:1b:44:11:3a:b7"]
        );
    }

    #[test]
    fn urls_and_emails_are_reported_whole() {
        let line = "GET http://example.com/a?b=1 user=jdoe@example.com";
        assert_eq!(values(line, ty::URL), vec!["http://example.com/a?b=1"]);
        assert_eq!(values(line, ty::EMAIL), vec!["jdoe@example.com"]);
    }

    #[test]
    fn prose_and_versions_do_not_become_hostnames() {
        // Over-reporting is the failure mode that matters: a hunt for a domain
        // must not match a line that never contained one.
        for line in [
            "Component is in the unavailable state.",
            "Loaded stack v6.1.7601.23505 ok",
            "wrote core.2481 to disk",
        ] {
            assert!(
                salvage(line).iter().all(|s| s.type_id != ty::HOSTNAME),
                "{line} produced a hostname"
            );
        }
        assert_eq!(
            values("connect to mail.example.com now", ty::HOSTNAME),
            vec!["mail.example.com"]
        );
    }

    #[test]
    fn output_is_deterministic_and_deduplicated() {
        // The event is canonicalized and hashed, so an unstable order would
        // produce a different fingerprint for identical bytes.
        let line = "a=10.0.0.1 b=10.0.0.1 c=10.0.0.2";
        let first = salvage(line);
        assert_eq!(first, salvage(line));
        assert_eq!(values(line, ty::IP_ADDRESS), vec!["10.0.0.1", "10.0.0.2"]);
    }

    #[test]
    fn a_hostile_record_cannot_attach_unbounded_observables() {
        let line = (0..500)
            .map(|i| format!("10.0.{}.{}", i / 256, i % 256))
            .collect::<Vec<_>>()
            .join(" ");
        assert!(salvage(&line).len() <= MAX_PER_RECORD);
    }

    #[test]
    fn never_panics_on_hostile_input() {
        for line in [
            "",
            ":::::",
            "=",
            "===",
            "日本語 10.0.0.1 テスト",
            "a@",
            "@b",
            "1.2.3.4.5.6",
            "[::1]:8080",
        ] {
            let _ = salvage(line);
        }
    }
}
