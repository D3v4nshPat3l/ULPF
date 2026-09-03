//! Fuzz every built-in decoder against arbitrary input.
//!
//! Decoders are the only code in ULPF that reads bytes an attacker chose, and
//! the release profile sets `panic = "abort"` — so a panic here is not a
//! recoverable error, it is the collector dying with its in-flight chain state.
//! The contract this target enforces is therefore narrow and absolute: for any
//! input at all, a decoder returns `Ok` or `Err`, and never panics.
//!
//! This target previously called an API that had not existed for some time —
//! constructors that were never defined, a two-argument `decode`, imports of
//! types that are not re-exported at the crate root — and `fuzz/` is not a
//! workspace member, so nothing ever compiled it. A char-boundary panic in the
//! XML decoder survived in the tree as a result. Keep it building.
//!
//! Run with:
//!   cargo +nightly fuzz run decoder_fuzz

#![no_main]

use libfuzzer_sys::fuzz_target;

use ulpf_decode::{
    cef::CefDecoder, csv::CsvDecoder, json::JsonDecoder, keyvalue::KeyValueDecoder,
    leef::LeefDecoder, regex_dec::RegexDecoder, syslog::SyslogDecoder, xml::XmlDecoder, Decoder,
};

fuzz_target!(|data: &[u8]| {
    // Decoders take &str; invalid UTF-8 is rejected upstream in the pipeline,
    // which stores the raw bytes and emits a minimal event instead.
    let Ok(text) = std::str::from_utf8(data) else {
        return;
    };

    let regex = RegexDecoder::new(&[
        r"^(?P<verdict>[A-Za-z ]+):\s+(?P<body>.*)$".to_string(),
        r"\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]".to_string(),
    ])
    .expect("the fixed patterns compile");

    let decoders: [&dyn Decoder; 9] = [
        &SyslogDecoder::new(),
        &SyslogDecoder::rfc3164_only(),
        &SyslogDecoder::rfc5424_only(),
        &KeyValueDecoder::default(),
        &CsvDecoder::default(),
        &CefDecoder,
        &LeefDecoder,
        &JsonDecoder,
        &XmlDecoder,
    ];

    for decoder in decoders {
        // The result is discarded on purpose: Err is a valid outcome for
        // arbitrary bytes, and a panic is the only thing being tested for.
        let _ = decoder.decode(text);
    }
    let _ = regex.decode(text);

    // A decoder that reports a body must hand back a slice of its own input,
    // or the next decoder in the chain reads memory that is not the event.
    if let Ok(decoded) = SyslogDecoder::new().decode(text) {
        if let Some(body) = decoded.body {
            assert!(
                body.len() <= text.len(),
                "the syslog body outgrew the line it came from"
            );
        }
    }
});
