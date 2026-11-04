//! vpsfort's outbox files on their way to the push service: account names and server addresses replaced, messages well formed.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| vpsfort_push_bot::fuzzing::alert(data));
