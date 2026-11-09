//! Honeypot hits from any holder of the web key: read and merged without a panic.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| vpsfort_web::fuzzing::honeypot_hits(data));
