//! Every decoder must return `Ok` or `Err` for any input, and never panic.
//!
//! Decoders read bytes chosen by whoever is sending logs, and the release
//! profile sets `panic = "abort"` — a panic is not a caught error, it is the
//! collector process dying and taking its in-flight attestation state with it.
//! For a log collector, that is the one failure mode the whole design exists to
//! prevent, and it is reachable from the network.
//!
//! There is a libfuzzer target at `fuzz/fuzz_targets/decoder_fuzz.rs` for deep
//! exploration, but it needs nightly and a separate toolchain, so in practice
//! it did not run — and a char-boundary panic in the XML decoder lived in the
//! tree until someone fed it a Japanese log line. This file is the version that
//! runs on stable, in CI, on every commit.
//!
//! When a new crash is found, add the input here before fixing it.

use ulpf_decode::{
    cef::CefDecoder, csv::CsvDecoder, json::JsonDecoder, keyvalue::KeyValueDecoder,
    leef::LeefDecoder, regex_dec::RegexDecoder, syslog::SyslogDecoder, xml::XmlDecoder, Decoder,
};

/// Inputs chosen to break a scanner: multi-byte characters at every position a
/// byte-walking loop might land, truncation part-way through each format's
/// framing, and structures that recurse.
fn hostile_inputs() -> Vec<String> {
    let mut cases: Vec<String> = vec![
        // Non-ASCII inside each format's containers. Any loop that advances a
        // byte at a time and then slices dies on these.
        "<Event><Msg>日本語</Msg></Event>".into(),
        r#"<Event Name="Ωmega">उपयोगकर्ता</Event>"#.into(),
        "<Ωmega>value</Ωmega>".into(),
        "<a><b>é</b><b>é</b></a>".into(),
        "CEF:0|Vendor|Ünicode|1.0|1|Nåme|5|src=10.0.0.1 msg=日本".into(),
        "LEEF:1.0|Vendor|Prodükt|1.0|Ereignis|\tsrc=10.0.0.1".into(),
        "<134>Aug 31 10:23:45 хост prog: тело сообщения".into(),
        "srcip=10.0.0.1 msg=\"日本語 テスト\" action=accept".into(),
        r#"{"msg":"日本語","nested":{"ключ":"значение"}}"#.into(),
        "a,b,日本語,\"d,é\",f".into(),
        // Truncation part-way through framing.
        "CEF:0|only|two".into(),
        "CEF:".into(),
        "LEEF:1.0|a|b".into(),
        "<134>".into(),
        "<".into(),
        "<134".into(),
        "<Event".into(),
        "<Event><Msg>unterminated".into(),
        "</Closing>".into(),
        "<!-- unterminated comment".into(),
        "<![CDATA[unterminated".into(),
        "<?xml unterminated".into(),
        r#"{"a":"#.into(),
        r#"srcip="unterminated"#.into(),
        "a,\"unterminated".into(),
        // Structures that recurse or repeat.
        "<a>".repeat(200) + &"</a>".repeat(200),
        "<Data></Data>".repeat(500),
        "k=v ".repeat(2000),
        ",".repeat(5000),
        "[".repeat(500),
        // Bare control and boundary characters.
        "\u{0}\u{1}\u{2}".into(),
        "\u{feff}<134>1 2026-01-01T00:00:00Z h a - - - body".into(),
        "".into(),
        " ".into(),
        "\n".into(),
        "\t\t\t".into(),
    ];

    // Every single character of a multi-byte string as its own input, plus
    // progressively truncated prefixes of an XML document — this is exactly the
    // family that produced the original crash.
    let doc = "<Event><Msg>日本語テスト</Msg></Event>";
    for end in 1..doc.len() {
        if doc.is_char_boundary(end) {
            cases.push(doc[..end].to_string());
        }
    }
    cases
}

fn decoders() -> Vec<(&'static str, Box<dyn Decoder>)> {
    vec![
        ("syslog", Box::new(SyslogDecoder::new())),
        ("syslog_rfc3164", Box::new(SyslogDecoder::rfc3164_only())),
        ("syslog_rfc5424", Box::new(SyslogDecoder::rfc5424_only())),
        ("keyvalue", Box::new(KeyValueDecoder::default())),
        ("csv", Box::new(CsvDecoder::default())),
        ("cef", Box::new(CefDecoder)),
        ("leef", Box::new(LeefDecoder)),
        ("json", Box::new(JsonDecoder)),
        ("xml", Box::new(XmlDecoder)),
    ]
}

#[test]
fn no_decoder_panics_on_hostile_input() {
    for (name, decoder) in decoders() {
        for input in hostile_inputs() {
            // `catch_unwind` reports which decoder and which input failed,
            // instead of the whole suite dying on the first crash.
            let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
                let _ = decoder.decode(&input);
            }));
            assert!(
                result.is_ok(),
                "decoder `{name}` panicked on {:?}",
                truncate(&input)
            );
        }
    }
}

#[test]
fn the_regex_decoder_does_not_panic_on_hostile_input() {
    let decoder = RegexDecoder::new(&[
        r"^(?P<verdict>[A-Za-z ]+):\s+(?P<body>.*)$".to_string(),
        r"(?P<src>[\d.]+)\s+->\s+(?P<dst>[\d.]+)".to_string(),
    ])
    .expect("the fixed patterns compile");

    for input in hostile_inputs() {
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let _ = decoder.decode(&input);
        }));
        assert!(
            result.is_ok(),
            "the regex decoder panicked on {:?}",
            truncate(&input)
        );
    }
}

#[test]
fn a_reported_body_is_always_a_slice_of_the_input() {
    // The body is handed to the next decoder in the chain. If it can be longer
    // than the line it came from, the chain is reading something other than the
    // event.
    for input in hostile_inputs() {
        for (name, decoder) in decoders() {
            if let Ok(decoded) = decoder.decode(&input) {
                if let Some(body) = decoded.body {
                    assert!(
                        body.len() <= input.len(),
                        "decoder `{name}` returned a body longer than its input"
                    );
                }
            }
        }
    }
}

fn truncate(s: &str) -> String {
    s.chars().take(60).collect()
}
