//! A decision log's hourly index as an attacker or a damaged disk may leave it, against a
//! log: a reader must land at the start of a line of the hour asked, or at the log's start.
//! Input: the index text, a NUL byte, the log.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    vpsfort::fuzzing::log_index(data);
});
