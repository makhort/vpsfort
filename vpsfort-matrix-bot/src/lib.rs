//! The bot as a library: the binary (`main.rs`) only reads the settings, the tests in
//! `tests/` drive the same code against a fake homeserver with a fake admin device, and the
//! fuzz targets in `fuzz/` reach it through [`fuzzing`].

pub mod api;
pub mod bot;
pub mod crypto;
pub mod fuzzing;
pub mod login;
pub mod state;

// shared with the other copy bots (../vpsfort-botlib)
pub use vpsfort_botlib::{logger, outbox, redact, seal, servers};
