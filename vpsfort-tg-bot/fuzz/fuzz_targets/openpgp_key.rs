//! The admin's OpenPGP key file: whatever is taken as a key must encrypt.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| vpsfort_tg_bot::fuzzing::openpgp_key(data));
