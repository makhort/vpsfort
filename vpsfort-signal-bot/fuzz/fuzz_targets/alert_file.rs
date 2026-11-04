//! vpsfort's outbox files as the bot reads them.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| vpsfort_signal_bot::fuzzing::alert_file(data));
