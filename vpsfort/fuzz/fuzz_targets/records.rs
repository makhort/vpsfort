//! Log lines in every format vpsfort reads, through the parsers and the engine.
#![no_main]

use std::sync::{Arc, OnceLock};

use vpsfort::config::Config;

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    static CFG: OnceLock<Arc<Config>> = OnceLock::new();
    vpsfort::fuzzing::records(CFG.get_or_init(vpsfort::fuzzing::config), data);
});
