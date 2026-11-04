//! The bot as a library: the binary (`main.rs`) only reads the settings and starts
//! signal-cli, the tests in `tests/` drive the same code against a fake signal-cli, and the
//! fuzz targets in `fuzz/` reach it through [`fuzzing`].

pub mod bot;
pub mod cli;
pub mod fuzzing;
pub mod rpc;
pub mod state;

// shared with the other copy bots (../vpsfort-botlib)
pub use vpsfort_botlib::{logger, outbox, redact, seal, servers};
