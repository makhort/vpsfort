//! libsignal's protobuf messages inside OMEMO keys.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| vpsfort_xmpp_bot::fuzzing::wire(data));
