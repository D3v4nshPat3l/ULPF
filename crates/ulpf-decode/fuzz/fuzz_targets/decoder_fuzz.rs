#![no_main]

use libfuzzer_sys::fuzz_target;
use ulpf_decode::{Decoder, RegexDecoder, XmlDecoder, LeefDecoder};
use ulpf_core::Value;
use std::collections::HashMap;

fuzz_target!(|data: &[u8]| {
    if let Ok(s) = std::str::from_utf8(data) {
        // Fuzz Regex Decoder
        if let Ok(decoder) = RegexDecoder::new(r"(?P<test>.*)") {
            let mut extracted = HashMap::new();
            let _ = decoder.decode(s, &mut extracted);
        }
        
        // Fuzz XML Decoder
        let xml_decoder = XmlDecoder::new("event", &HashMap::new());
        let mut extracted = HashMap::new();
        let _ = xml_decoder.decode(s, &mut extracted);

        // Fuzz LEEF Decoder
        let leef_decoder = LeefDecoder::new();
        let mut extracted = HashMap::new();
        let _ = leef_decoder.decode(s, &mut extracted);
    }
});
