//! A decision log (actions.jsonl, as peers and older versions wrote it) through the readers:
//! the dashboard's log view and the live abuse report.
#![no_main]

libfuzzer_sys::fuzz_target!(|data: &[u8]| {
    vpsfort::fuzzing::actions_log(data);
});
